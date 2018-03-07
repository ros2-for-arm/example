/*
* Copyright (c) 2018, ARM Limited.
*
* SPDX-License-Identifier: Apache-2.0
*/

#include "rclcpp/rclcpp.hpp"

#include "aes_custom_interface/msg/aes_message_certify.hpp"
#include "aes_custom_interface/srv/get_symm_secret.hpp"

#include <string>

extern "C" {
#include <aes_api.h>
#include <hmac_api.h>
#include <rsa_api.h>
#include <ta_public.h>
#include <tee_client_api.h>
#include <teec_utils.h>
}

// Max number of byte for a message.
#define SUBSCRIBER_MAX_MESSAGE_SIZE 18

using namespace std;
using namespace placeholders;
using namespace aes_custom_interface::srv;
using namespace aes_custom_interface::msg;

class AesSubscriber : public rclcpp::Node {
public:
  AesSubscriber(string topic_name, string service_name)
  : Node("subscriber_and_client") {
    TEEC_UUID uuid = TA_TRUSTED_UUID;

    ca_teec_exit_on_failure(&ctx, &sess, ca_teec_open_session(uuid, &ctx, &sess));

    allocate_memory_ta();

    // Wait for the Secret key
    waiting_for_secret(service_name);

    // Decrypt the key and set it to default decryption key in the TA
    ca_teec_exit_on_failure(&ctx, &sess, ca_aes_decrypt_and_allocate_key(&sess,
      &aes_encrypted_key_shm, aes_encrypted_key_shm.size));

    // Subscribe to the corresponding topic
    subscription = this->create_subscription<AesMessageCertify>(topic_name,
      std::bind(&AesSubscriber::topic_callback, this, _1));

    RCLCPP_INFO(this->get_logger(), "Subscriber initialized with topic:\"%s\", service:\"%s\"",
      topic_name.c_str(), service_name.c_str())
  }

  GetSymmSecret_Response::SharedPtr
  send_request(rclcpp::Node::SharedPtr node,
    rclcpp::Client<GetSymmSecret>::SharedPtr client,
    GetSymmSecret_Request::SharedPtr request)
  {
    auto result = client->async_send_request(request);
    // Wait for the result.
    if (rclcpp::spin_until_future_complete(node, result) ==
      rclcpp::executor::FutureReturnCode::SUCCESS) {
      return result.get();
    } else {
      return NULL;
    }
  }

private:
  void allocate_memory_ta()
  {
    // Used to store the published message
    ca_teec_exit_on_failure(&ctx, &sess, ca_teec_allocate_shared_memory(&ctx, &clear_message_shm,
      SUBSCRIBER_MAX_MESSAGE_SIZE, TEEC_MEM_INPUT));
    // Used to store the digest of the message signed by AES
    ca_teec_exit_on_failure(&ctx, &sess, ca_teec_allocate_shared_memory(&ctx, &sha_shm,
      HMAC_API_SHA1_SIZE_BYTE, TEEC_MEM_INPUT));

    // Used to authenticate the secret key send. Store the RSA digest of AES key
    ca_teec_exit_on_failure(&ctx, &sess, ca_teec_allocate_shared_memory(&ctx, &sha1_rsa_signed_shm,
      RSA_API_SIZE_ENCRYPTED_BYTE, TEEC_MEM_INPUT));
    // Used to store the incomming RSA encrypted AES key
    ca_teec_exit_on_failure(&ctx, &sess, ca_teec_allocate_shared_memory(&ctx,
      &aes_encrypted_key_shm, RSA_API_SIZE_ENCRYPTED_BYTE, TEEC_MEM_INPUT));
  }

  void waiting_for_secret(string service)
  {
    auto client_ = this->create_client<GetSymmSecret>(service);

    while (!client_->wait_for_service(std::chrono::seconds(1))) {
      if (!rclcpp::ok()) {
        RCLCPP_ERROR(this->get_logger(), "Interrupted before service came !");
        ca_teec_close_session(&ctx, &sess);
        exit(0);
      }
      RCLCPP_INFO(this->get_logger(), "Waiting for the secret key.");
    }

    auto request = std::make_shared<GetSymmSecret::Request>();
    bool validated = false;
    while (!validated) {
      auto answer_service = client_->async_send_request(request);
      if (rclcpp::spin_until_future_complete(this->get_node_base_interface(),
        answer_service) != rclcpp::executor::FutureReturnCode::SUCCESS)
      {
        RCLCPP_ERROR(this->get_logger(), "Service could not deliver the secret... Exiting");
        ca_teec_close_session(&ctx, &sess);
        exit(-1);
      }

      // Fill the shared memory with the AES secret encrypted by RSA
      auto result = answer_service.get();
      uint8_t *aes_secret = (uint8_t *)aes_encrypted_key_shm.buffer;
      for (uint32_t i = 0; i < result->secret.size() && i < aes_encrypted_key_shm.size; i++) {
        aes_secret[i] = result->secret[i];
      }

      // Fill the shared memory with the RSA signature of the digested key
      uint8_t *rsa_digest = (uint8_t *)sha1_rsa_signed_shm.buffer;
      for (uint32_t i = 0; i < result->sha.size() && i < sha1_rsa_signed_shm.size; i++) {
        rsa_digest[i] = result->sha[i];
      }

      // Check that the digest is valid
      validated = ca_rsa_verify(&sess, &aes_encrypted_key_shm, aes_encrypted_key_shm.size,
        &sha1_rsa_signed_shm, sha1_rsa_signed_shm.size);
    }
  }

  void topic_callback(const AesMessageCertify::SharedPtr msg)
  {
    // Copy the content of the message into the shared memory location
    uint8_t *clear_cast = (uint8_t *)clear_message_shm.buffer;
    for (uint32_t i = 0; i < msg->message.size() && i < clear_message_shm.size; i++) {
      clear_cast[i] = msg->message[i];
    }

    // Copy the content of digest into the shared memory location
    uint8_t *sha_cast = (uint8_t *)sha_shm.buffer;
    for (uint32_t i = 0; i < msg->sha.size() && i < sha_shm.size; i++) {
      sha_cast[i] = msg->sha[i];
    }

    // Compare the digest of the message with the actual digest sent
    if (ca_hmac_compare(&sess, &clear_message_shm, &sha_shm, msg->message.size()))
    {
      std::string message((const char *)clear_cast);
      RCLCPP_INFO(this->get_logger(), "Message authenticated: \"%s\"", clear_cast);
    } else {
      RCLCPP_INFO(this->get_logger(), "Message non authenticated");
    }
  }

  TEEC_Context ctx;
  TEEC_Session sess;
  TEEC_SharedMemory clear_message_shm;
  TEEC_SharedMemory sha_shm;
  TEEC_SharedMemory aes_encrypted_key_shm;
  TEEC_SharedMemory sha1_rsa_signed_shm;

  TEEC_SharedMemory rsa_sha_shm;
  rclcpp::Subscription<AesMessageCertify>::SharedPtr subscription;
};

int main(int argc, char *argv[])
{
  string topic("secure_msg");
  string service("service_aes");

  rclcpp::init(argc, argv);
  rclcpp::executors::MultiThreadedExecutor executor;

  auto node = std::make_shared<AesSubscriber>(topic, service);
  rclcpp::Rate loop_rate(10);
  executor.add_node(node);

  while (rclcpp::ok()) {
    executor.spin_some();
    loop_rate.sleep();
  }

  return 0;
}

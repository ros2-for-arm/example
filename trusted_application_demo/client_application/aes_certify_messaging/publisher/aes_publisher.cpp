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
#define PUBLISHER_MAX_MESSAGE_SIZE 18
// Number of messages that will be sent by the publisher.
#define PUBLISHER_MAX_NUMBER_MESSAGE 100

using namespace std;
using namespace placeholders;
using namespace aes_custom_interface::srv;
using namespace aes_custom_interface::msg;

class AesPublisher : public rclcpp::Node
{
public:
  AesPublisher(string topic_name, string service_name)
  : Node("publisher_and_server")
  {
    publisher = this->create_publisher<AesMessageCertify>(topic_name, rmw_qos_profile_default);
    TEEC_UUID uuid = TA_TRUSTED_UUID;

    ca_teec_exit_on_failure(&ctx, &sess, ca_teec_open_session(uuid, &ctx, &sess));

    allocate_memory_ta();

    // Create the AES secret and encrypt it with RSA
    ca_teec_exit_on_failure(&ctx, &sess, ca_aes_generate_encrypted_key(&sess,
      &aes_key_rsa_encrypted_shm, RSA_API_SIZE_ENCRYPTED_BYTE));

    ca_teec_exit_on_failure(&ctx, &sess, ca_rsa_certify(&sess, &aes_key_rsa_encrypted_shm,
      aes_key_rsa_encrypted_shm.size, &sha1_rsa_certified_shm));

    // Create the service used to ask for the secret
    auto bind_service_handler = bind(&AesPublisher::handle_service, this, _1, _2, _3);
    publisher_service = this->create_service<GetSymmSecret>(service_name,
      bind_service_handler, rmw_qos_profile_default);

    // Message ID used for all the messages.
    message_id = 0;

    RCLCPP_INFO(this->get_logger(), "Publisher initialized with topic: \"%s\", service: \"%s\"",
      topic_name.c_str(), service_name.c_str())
  }

  bool send_msg(void)
  {
    // Create the message at the correct memory location
    char *clear_message_cast = (char *)clear_message_shm.buffer;
    snprintf(clear_message_cast, PUBLISHER_MAX_MESSAGE_SIZE,
             "Hello World %04d!", message_id++);

    // Certify the message
    ca_teec_exit_on_failure(&ctx, &sess, ca_hmac_compute(&sess, &clear_message_shm, &sha1_hmac_shm,
      clear_message_shm.size));

    auto aes_message = std::make_shared<AesMessageCertify>();
    aes_message->message.assign(clear_message_cast, clear_message_cast + clear_message_shm.size);
    uint8_t *castsha_shm = (uint8_t *)sha1_hmac_shm.buffer;
    aes_message->sha.assign(castsha_shm, castsha_shm + sha1_hmac_shm.size);

    RCLCPP_INFO(this->get_logger(), "Publishing certified message: \"%s\"", clear_message_cast)
    publisher->publish(aes_message);

    if (PUBLISHER_MAX_NUMBER_MESSAGE == message_id) {
      RCLCPP_INFO(this->get_logger(), "Exit publisher")
      ca_teec_close_session(&ctx, &sess);
      return false;
    }

    return true;
  }

public:
  void handle_service(const std::shared_ptr<rmw_request_id_t> request_header,
    const std::shared_ptr<GetSymmSecret::Request> request,
    const std::shared_ptr<GetSymmSecret::Response> response)
  {
    (void)request_header;
    (void)request;

    uint8_t *aes_key = (uint8_t *)aes_key_rsa_encrypted_shm.buffer;
    response->secret.assign(aes_key, aes_key + aes_key_rsa_encrypted_shm.size);

    uint8_t *rsa_sha = (uint8_t *)sha1_rsa_certified_shm.buffer;
    response->sha.assign(rsa_sha, rsa_sha + sha1_rsa_certified_shm.size);
  }

private:
  void allocate_memory_ta()
  {
    // Allocate shared memory for the input message in clear.
    ca_teec_exit_on_failure(&ctx, &sess, ca_teec_allocate_shared_memory(&ctx, &clear_message_shm,
      PUBLISHER_MAX_MESSAGE_SIZE, TEEC_MEM_INPUT));

    // Allocate shared memory for the hashed message:
    // sha1_hmac_shm is the hash of the published messaged encrypted through AES
    ca_teec_exit_on_failure(&ctx, &sess, ca_teec_allocate_shared_memory(&ctx, &sha1_hmac_shm,
      HMAC_API_SHA1_SIZE_BYTE, TEEC_MEM_OUTPUT));

    // sha1_rsa_certified_shm is the hash of the published messaged encrypted
    //  through RSA secret when a node requests it through the service
    ca_teec_exit_on_failure(&ctx, &sess, ca_teec_allocate_shared_memory(&ctx,
      &sha1_rsa_certified_shm, RSA_API_SIZE_ENCRYPTED_BYTE, TEEC_MEM_OUTPUT));

    // This buffer contains the AES key encrypted through RSA
    ca_teec_exit_on_failure(&ctx, &sess, ca_teec_allocate_shared_memory(&ctx,
      &aes_key_rsa_encrypted_shm, RSA_API_SIZE_ENCRYPTED_BYTE, TEEC_MEM_INPUT | TEEC_MEM_OUTPUT));
  }

  TEEC_Context ctx;
  TEEC_Session sess;
  TEEC_SharedMemory clear_message_shm;
  TEEC_SharedMemory sha1_hmac_shm;
  TEEC_SharedMemory aes_key_rsa_encrypted_shm;
  TEEC_SharedMemory sha1_rsa_certified_shm;

  rclcpp::Publisher<AesMessageCertify>::SharedPtr publisher;
  rclcpp::Service<GetSymmSecret>::SharedPtr publisher_service;

  uint32_t message_id;
};

int main(int argc, char *argv[])
{
  rclcpp::init(argc, argv);
  rclcpp::executors::MultiThreadedExecutor executor;

  string topic("secure_msg");
  string service("service_aes");

  auto node = std::make_shared<AesPublisher>(topic, service);
  rclcpp::Rate loop_rate(10);
  executor.add_node(node);
  bool exit_flag = false;

  while (rclcpp::ok() && !exit_flag) {
    if (!node->send_msg()) {
      exit_flag = true;
    }
    // Handle ROS events
    executor.spin_some();
    loop_rate.sleep();
  }

  return 0;
}

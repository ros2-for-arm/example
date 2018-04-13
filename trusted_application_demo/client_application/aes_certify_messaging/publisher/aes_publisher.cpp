//
// Copyright (c) 2018, ARM Limited.
//
// SPDX-License-Identifier: Apache-2.0
//

#include <tee_client_api.h>
#include <ta_security_api/ta_public.h>
#include <ca_security_api/aes_api.h>
#include <ca_security_api/hmac_api.h>
#include <ca_security_api/rsa_api.h>
#include <ca_security_api/teec_utils.h>

#include <string>
#include <memory>

#include "rclcpp/rclcpp.hpp"
#include "aes_custom_interface/msg/aes_message_certify.hpp"
#include "aes_custom_interface/srv/get_symm_secret.hpp"

using AesMessageCertify = aes_custom_interface::msg::AesMessageCertify;
using GetSymmSecret = aes_custom_interface::srv::GetSymmSecret;

class AesPublisher : public rclcpp::Node
{
public:
  AesPublisher(std::string topic_name, std::string service_name, uint32_t max_message_size,
    uint32_t max_message_send)
  : Node("publisher_and_server")
  {
    this->max_message_size = max_message_size;
    this->max_message_send = max_message_send;

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
    auto bind_service_handler = std::bind(&AesPublisher::handle_service, this,
        std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
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
    char * clear_message_cast = reinterpret_cast<char *>(clear_message_shm.buffer);
    snprintf(clear_message_cast, max_message_size, "Hello World %04d!", message_id++);

    // Certify the message
    ca_teec_exit_on_failure(&ctx, &sess, ca_hmac_compute(&sess, &clear_message_shm, &sha1_hmac_shm,
      clear_message_shm.size));

    auto aes_message = std::make_shared<AesMessageCertify>();
    aes_message->message.assign(clear_message_cast, clear_message_cast + clear_message_shm.size);
    uint8_t * castsha_shm = reinterpret_cast<uint8_t *>(sha1_hmac_shm.buffer);
    aes_message->sha.assign(castsha_shm, castsha_shm + sha1_hmac_shm.size);

    RCLCPP_INFO(this->get_logger(), "Publishing certified message: \"%s\"", clear_message_cast)
    publisher->publish(aes_message);

    if (max_message_send == message_id) {
      RCLCPP_INFO(this->get_logger(), "Exit publisher")
      ca_teec_close_session(&ctx, &sess);
      return false;
    }

    return true;
  }

private:
  void handle_service(
    const std::shared_ptr<rmw_request_id_t> request_header,
    const std::shared_ptr<GetSymmSecret::Request> request,
    const std::shared_ptr<GetSymmSecret::Response> response)
  {
    // Unused arguments
    (void)request_header;
    (void)request;

    // Reply to the service request by sending the AES Key and RSA SHA
    uint8_t * aes_key = reinterpret_cast<uint8_t *>(aes_key_rsa_encrypted_shm.buffer);
    response->secret.assign(aes_key, aes_key + aes_key_rsa_encrypted_shm.size);

    uint8_t * rsa_sha = reinterpret_cast<uint8_t *>(sha1_rsa_certified_shm.buffer);
    response->sha.assign(rsa_sha, rsa_sha + sha1_rsa_certified_shm.size);
  }

  void allocate_memory_ta()
  {
    // Allocate shared memory for the input message in clear.
    ca_teec_exit_on_failure(&ctx, &sess, ca_teec_allocate_shared_memory(&ctx, &clear_message_shm,
      max_message_size, TEEC_MEM_INPUT));

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

  // Max number of byte for a message.
  uint32_t max_message_size;
  // Number of messages that will be sent by the publisher.
  uint32_t max_message_send;

  rclcpp::Publisher<AesMessageCertify>::SharedPtr publisher;
  rclcpp::Service<GetSymmSecret>::SharedPtr publisher_service;

  uint32_t message_id;
};

int main(int argc, char * argv[])
{
  rclcpp::init(argc, argv);
  rclcpp::executors::MultiThreadedExecutor executor;

  std::string topic("secure_msg");
  std::string service("service_aes");
  uint32_t max_message_size = 18;
  uint32_t max_message_send = 100;

  for (int i = 1; i < argc; i++) {
    if (i + 1 != argc) {
      if (strncmp(argv[i], "-m", 2) != 0) {
        max_message_size = strtoul(argv[i + 1], NULL, 10);
      } else if (strncmp(argv[i], "-s", 2) != 0) {
        max_message_send = strtoul(argv[i + 1], NULL, 10);
      } else {
        std::cout << "Usage: "<< argv[0] << "\n";
        std::cout << " [-m <unsigned int>] maximum message size\n";
        std::cout << " [-s <unsigned int>] number of message that will be published\n";
        exit(0);
      }
    }
  }

  auto node = std::make_shared<AesPublisher>(topic, service, max_message_size, max_message_send);
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

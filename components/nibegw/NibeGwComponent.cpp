#include "NibeGwComponent.h"

#ifdef USE_NIBEGW_THERMAESTRO
#include "esphome/core/hal.h"
#include "esphome/core/helpers.h"
#ifdef USE_WIFI
#include "esphome/components/wifi/wifi_component.h"
#endif
#ifdef USE_ESP32
#include <esp_heap_caps.h>
#endif
#endif

namespace esphome {

namespace nibegw {

NibeGwComponent::NibeGwComponent(esphome::GPIOPin *dir_pin) {
  gw_ = new NibeGw(this, dir_pin);
  gw_->setCallback(
      std::bind(&NibeGwComponent::callback_msg_received, this, std::placeholders::_1, std::placeholders::_2),
      std::bind(&NibeGwComponent::callback_msg_token_received, this, std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3));
}

static request_data_type dedup(const uint8_t *data, int len, uint8_t val) {
  request_data_type message;
  uint8_t value = ~val;
  for (int i = 5; i < len - 1; i++) {
    if (data[i] == val && value == val) {
      value = ~val;
      continue;
    }
    value = data[i];
    message.push_back(value);
  }
  return message;
}

void NibeGwComponent::callback_msg_received(const uint8_t *data, int len) {
  {
    request_key_type key{data[2] | (data[1] << 8), static_cast<uint8_t>(data[3])};
    const auto &it = message_listeners_.find(key);
    if (it != message_listeners_.end()) {
      auto deduped = dedup(data, len, STARTBYTE_MASTER);
      for (auto &listener : it->second) {
        listener(deduped);
      }
    }
  }

#ifdef USE_NIBEGW_THERMAESTRO
  if (tgw_ && tgw_->control) {
    thermaestro_exchange_(data, len);
  }
#endif

  if (!is_connected_) {
    return;
  }

  /* always sending standard data from modbus read token */
  auto &udp_read_ = requests_sockets_[request_key_type(MODBUS40, READ_TOKEN)].socket;
  if (!udp_read_) {
    return;
  }

  // Send to all UDP targets
  for (auto &&[target, timestamp] : udp_targets_) {
    int result = udp_read_->sendto(data, len, 0, (sockaddr *) &target.storage, target.len);
    if (result < 0) {
      ESP_LOGW(TAG, "UDP sendto failed to %s, error: %d", target.str().c_str(), errno);
    }
  }
}

void NibeGwComponent::recv_local_socket(socket_ptr_type &fd, int address, int token) {
  request_data_type request(MAX_DATA_LEN);

  socket_address from;
  int n = fd->recvfrom(request.data(), request.size(), (sockaddr *) &from.storage, &from.len);
  if (n < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      ESP_LOGW(TAG, "recvfrom error on read socket: %d", errno);
    }
    return;
  }
  request.resize(n);

  if (udp_sources_.size() &&
      std::none_of(udp_sources_.begin(), udp_sources_.end(), [&](auto &source) { return from.matches(source); })) {
    ESP_LOGW(TAG, "UDP Packet wrong ip ignored %s", from.str().c_str());
    return;
  }

  if (gw_->checkSlaveData(request.data(), request.size()) != PACKET_OK) {
    ESP_LOGW(TAG, "Received invalid packet from %s, %d bytes", from.str().c_str(), n);
    return;
  }

  /* store this as a new target */
  uint32_t now = millis();
  auto [it, inserted] = udp_targets_.insert_or_assign(from, now);
  if (inserted) {
    ESP_LOGI(TAG, "New target added %s", from.str().c_str());
  }

#ifdef USE_NIBEGW_THERMAESTRO
  if (tgw_ && tgw_->engine) {
    // The engine tells a protocol client when a plain request pushes its request out.
    tgw_->engine->submit_plain(address, token, std::move(request), now_us_());
    return;
  }
#endif
  add_queued_request(address, token, std::move(request));
}

static int copy_request(const request_data_type &request, uint8_t *data) {
  auto len = std::min(request.size(), (size_t) MAX_DATA_LEN);
  std::copy_n(request.begin(), len, data);
  return len;
}

int NibeGwComponent::callback_msg_token_received(uint16_t address, uint8_t command, uint8_t *data) {
  request_key_type key{address, command};

#ifdef USE_NIBEGW_THERMAESTRO
  if (tgw_ && tgw_->engine) {
    uint64_t start = now_us_();
    tgw_->bus.last_token_us = start;
    tgw_->reply = tgw::Exchange::Reply::NONE;
    tgw_->reply_len = 0;
    const QueuedRequest *sent = tgw_->engine->reply_for(address, command, start);
    if (sent != nullptr) {
      auto len = copy_request(sent->data, data);
      tgw_->reply = tgw::Exchange::Reply::QUEUED;
      tgw_->reply_len = len;
      tgw_->reply_us = start;
      tgw_->control->note_reply_prep(now_us_() - start);
      ESP_LOGD(TAG, "Response to address: 0x%x token: 0x%x bytes: %d", std::get<0>(key), std::get<1>(key), len);
      return len;
    }
  } else
#endif
  {
    const auto &it = requests_.find(key);
    if (it != requests_.end()) {
      auto &queue = it->second;
      if (!queue.empty()) {
        auto len = copy_request(queue.front().data, data);
        queue.pop_front();
        ESP_LOGD(TAG, "Response to address: 0x%x token: 0x%x bytes: %d", std::get<0>(key), std::get<1>(key), len);
        return len;
      }
    }
  }

  {
    const auto &it = requests_provider_.find(key);
    if (it != requests_provider_.end()) {
      auto len = copy_request(it->second(), data);
      ESP_LOGD(TAG, "Response to address: 0x%x token: 0x%x bytes: %d", std::get<0>(key), std::get<1>(key), len);
#ifdef USE_NIBEGW_THERMAESTRO
      if (tgw_ && len > 0) {
        tgw_->reply = tgw::Exchange::Reply::CONSTANT;
        tgw_->reply_len = len;
        tgw_->reply_us = now_us_();
      }
#endif
      return len;
    }
  }

  return 0;
}

void NibeGwComponent::setup() {
  ESP_LOGI(TAG, "Starting up");
  gw_->connect();
}

void NibeGwComponent::dump_config() {
  ESP_LOGCONFIG(TAG, "NibeGw");
  for (auto &&[address, timeout] : udp_targets_) {
    ESP_LOGCONFIG(TAG, " Target: %s", address.str().c_str());
  }
  for (auto &&address : udp_sources_) {
    ESP_LOGCONFIG(TAG, " Source: %s", address.str().c_str());
  }
  for (auto const &x : requests_sockets_) {
    ESP_LOGCONFIG(TAG, " Handler %x:%x Port: %d", std::get<0>(x.first), std::get<1>(x.first), x.second.port);
  }
  for (auto const &x : message_listeners_) {
    ESP_LOGCONFIG(TAG, " Listeners %x:%x Count: %zu", std::get<0>(x.first), std::get<1>(x.first), x.second.size());
  }
#ifdef USE_NIBEGW_THERMAESTRO
  if (tgw_) {
    ESP_LOGCONFIG(TAG, " Thermaestro gateway protocol: port %d, %d clients at most, %s", tgw_->port,
                  tgw_->settings.max_clients, tgw_->settings.has_psk ? "a key required" : "no key");
  }
#endif
}

socket_ptr_type NibeGwComponent::bind_local_socket(int port) {
  auto fd = socket::socket_ip_loop_monitored(SOCK_DGRAM, 0);
  if (fd) {
    // Set non-blocking
    fd->setblocking(false);

    socket_address address(port);

    if (fd->bind((sockaddr *) &address.storage, address.len) < 0) {
      ESP_LOGE(TAG, "Failed to bind socket to port %d, error: %d", port, errno);
      fd.reset();
    } else {
      ESP_LOGI(TAG, "UDP socket bound to port %d", port);
    }
  } else {
    ESP_LOGE(TAG, "Failed to create socket, error: %d", errno);
  }
  return fd;
}

void NibeGwComponent::run_request_socket(const request_key_type &key, request_socket_type &data) {
  if (!is_connected_) {
    if (data.socket) {
      ESP_LOGI(TAG, "UDP socket released for port %d", data.port);
      data.socket.reset();
    }
    return;
  }

  if (!data.socket) {
    data.socket = bind_local_socket(data.port);
  }

  if (!data.socket) {
    return;
  }

  if (!data.socket->ready()) {
    return;
  }

  auto &[address, token] = key;
  recv_local_socket(data.socket, address, token);
}

void NibeGwComponent::loop() {
  // Handle network connection state
  if (network::is_connected()) {
    if (!is_connected_) {
      ESP_LOGI(TAG, "Connecting network ports.");
      is_connected_ = true;
    }
  } else {
    if (is_connected_) {
      ESP_LOGI(TAG, "Disconnecting network ports.");
      is_connected_ = false;
    }
  }

  uint32_t now = millis();

  // Static targets are always active
  for (auto &target : udp_targets_static_) {
    udp_targets_[target] = now;
  }

  // Check for timeouts on targets
  std::erase_if(udp_targets_, [&](const auto &item) { return now - item.second > TARGET_TIMEOUT_MS; });

  // Poll sockets for incoming packets
  for (auto &[key, data] : requests_sockets_) {
    run_request_socket(key, data);
  }

#ifdef USE_NIBEGW_THERMAESTRO
  if (tgw_) {
    run_thermaestro_();
  }
#endif

  // Handle high frequency loop requirement
  if (gw_->messageStillOnProgress()) {
    high_freq_.start();
  } else {
    high_freq_.stop();
  }
  gw_->loop();
}

#ifdef USE_NIBEGW_THERMAESTRO
// --- the Thermaestro gateway protocol ------------------------------------------------------

uint64_t NibeGwComponent::now_us_() {
  // micros() wraps after 71 minutes; the protocol's times don't.
  uint32_t now = micros();
  if (now < last_micros_) {
    micros_high_ += uint64_t(1) << 32;
  }
  last_micros_ = now;
  return micros_high_ | now;
}

void NibeGwComponent::setup_thermaestro_() {
  // On the first loop pass, once every component has set up: the virtual RMU40s have
  // added their addresses to the acknowledged ones by then.
  auto &t = *tgw_;
  std::set<request_key_type> keys;
  for (const auto &[key, handler] : requests_sockets_) {
    keys.insert(key);
  }
  t.engine =
      std::make_unique<tgw::Engine>(requests_, keys, REQUESTS_QUEUE_MAX, uint32_t(t.settings.answer_timeout_ms) * 1000);

  auto &s = t.settings;
  uint8_t boot[4];
  random_bytes(boot, sizeof(boot));
  s.boot_id = boot[0] | (boot[1] << 8) | (boot[2] << 16) | (uint32_t(boot[3]) << 24);
  s.started_us = now_us_();
  s.impl_version = ESPHOME_VERSION;
  s.random = [](uint8_t *out, size_t len) { random_bytes(out, len); };
  auto read = requests_sockets_.find(request_key_type(MODBUS40, READ_TOKEN));
  auto write = requests_sockets_.find(request_key_type(MODBUS40, WRITE_TOKEN));
  s.plain_read_port = read != requests_sockets_.end() ? read->second.port : 0;
  s.plain_write_port = write != requests_sockets_.end() ? write->second.port : 0;
  for (const auto &source : udp_sources_) {
    if (source.storage.ss_family == AF_INET) {
      s.sources.push_back(reinterpret_cast<const sockaddr_in *>(&source.storage)->sin_addr.s_addr);
    }
  }
  s.acknowledged.assign(acknowledged_.begin(), acknowledged_.end());
  s.platform_health = [](std::vector<tgw::Option> &options) {
#ifdef USE_WIFI
    if (wifi::global_wifi_component != nullptr) {
      options.push_back(tgw::Option::u8(tgw::Tag::WIFI_RSSI, wifi::global_wifi_component->wifi_rssi()));
    }
#endif
#ifdef USE_ESP32
    options.push_back(tgw::Option::u32(tgw::Tag::FREE_HEAP, heap_caps_get_free_size(MALLOC_CAP_INTERNAL)));
#endif
  };
  t.control = std::make_unique<tgw::Control>(*t.engine, t.bus, s);
  ESP_LOGI(TAG, "Thermaestro gateway protocol on port %d, boot id %08x", t.port, (unsigned) s.boot_id);
}

void NibeGwComponent::run_thermaestro_() {
  if (!tgw_->control) {
    setup_thermaestro_();
  }
  auto &t = *tgw_;
  uint64_t now = now_us_();
  if (t.last_loop_us != 0) {
    t.control->note_loop_gap((now - t.last_loop_us) / 1000);
  }
  t.last_loop_us = now;
  if (gw_->messageStillOnProgress()) {
    t.bus.last_byte_us = now;
  }

  if (!is_connected_) {
    if (t.socket) {
      ESP_LOGI(TAG, "UDP socket released for port %d", t.port);
      t.socket.reset();
    }
  } else {
    if (!t.socket) {
      t.socket = bind_local_socket(t.port);
    }
    if (t.socket && t.socket->ready()) {
      uint8_t buffer[tgw::MAX_DATAGRAM + 1];
      // A few per pass, so the bus isn't kept waiting.
      for (int i = 0; i < 4; i++) {
        socket_address from;
        int n = t.socket->recvfrom(buffer, sizeof(buffer), (sockaddr *) &from.storage, &from.len);
        if (n < 0) {
          break;
        }
        if (from.storage.ss_family != AF_INET) {
          continue;
        }
        const auto *in = reinterpret_cast<const sockaddr_in *>(&from.storage);
        tgw::Peer peer{in->sin_addr.s_addr, ntohs(in->sin_port)};
        send_thermaestro_(t.control->handle(buffer, n, peer, now_us_()));
      }
    }
  }

  if (now - t.last_tick_us >= 100000) {
    t.last_tick_us = now;
    send_thermaestro_(t.control->tick(now));
  }
}

void NibeGwComponent::thermaestro_exchange_(const uint8_t *data, int len) {
  auto &t = *tgw_;
  uint64_t now = now_us_();
  uint16_t address = len >= 3 ? (data[1] << 8) | data[2] : 0;
  bool acknowledged = acknowledged_.count(address) != 0;
  bool replied = t.reply != tgw::Exchange::Reply::NONE;
  auto exchange = tgw::make_exchange(data, len, acknowledged, t.reply, t.reply_len, now, replied ? t.reply_us : 0);
  t.reply = tgw::Exchange::Reply::NONE;
  t.reply_len = 0;

  auto &b = t.bus;
  b.last_byte_us = now;
  if (exchange.parsed) {
    b.frames_ok++;
    if (acknowledged && exchange.telegram_len == 6) {
      (replied ? b.tokens_with_reply : b.tokens_ack_only)++;
    }
    if (replied && exchange.trailer == tgw::bus::NAK_BYTE) {
      b.pump_naks++;
    } else if (replied && exchange.trailer < 0) {
      b.no_ack_seen++;
    }
  } else if (exchange.telegram_len != 0 && size_t(len) >= exchange.telegram_len) {
    b.crc_errors++;
    if (acknowledged) {
      b.naks_sent++;
    }
  }
  send_thermaestro_(t.control->on_exchange(exchange));
}

void NibeGwComponent::send_thermaestro_(const std::vector<tgw::Datagram> &datagrams) {
  auto &t = *tgw_;
  for (const auto &d : datagrams) {
    if (!t.socket) {
      t.control->stats.events_dropped++;
      continue;
    }
    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(d.to.port);
    to.sin_addr.s_addr = d.to.ip;
    if (t.socket->sendto(d.data.data(), d.data.size(), 0, (sockaddr *) &to, sizeof(to)) < 0) {
      t.control->stats.udp_send_errors++;
    }
  }
}
#endif

}  // namespace nibegw
}  // namespace esphome

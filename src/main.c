/**
 * Copyright (c) 2017, Łukasz Marcin Podkalicki <lpodkalicki@gmail.com>
 * ESP32/016
 * WiFi Sniffer.
 */

#include "driver/gpio.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "freertos/FreeRTOS.h"
#include "nvs_flash.h"

#define LED_GPIO_PIN GPIO_NUM_5
#define WIFI_CHANNEL_MAX (13)
#define WIFI_CHANNEL_SWITCH_INTERVAL (500)

static wifi_country_t wifi_country = {
    .cc = "JP", .schan = 1, .nchan = 14, .policy = WIFI_COUNTRY_POLICY_AUTO};

typedef struct {
  unsigned frame_ctrl : 16;
  unsigned duration_id : 16;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned sequence_ctrl : 16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(
    wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff,
                                        wifi_promiscuous_pkt_type_t type);

void app_main(void) {
  uint8_t level = 0, channel = 1;

  /* setup */
  wifi_sniffer_init();
  gpio_set_direction(LED_GPIO_PIN, GPIO_MODE_OUTPUT);

  /* loop */
  while (true) {
    gpio_set_level(LED_GPIO_PIN, level ^= 1);
    vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
    wifi_sniffer_set_channel(channel);
    channel = (channel % WIFI_CHANNEL_MAX) + 1;
  }
}

esp_err_t event_handler(void *ctx, system_event_t *event) { return ESP_OK; }

void wifi_sniffer_init(void) {
  nvs_flash_init();
  tcpip_adapter_init();
  ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_country(
      &wifi_country)); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  ESP_ERROR_CHECK(esp_wifi_start());
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
}

void wifi_sniffer_set_channel(uint8_t channel) {
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type) {
  switch (type) {
    case WIFI_PKT_MGMT:
      return "MGMT";
    case WIFI_PKT_DATA:
      return "DATA";
    default:
    case WIFI_PKT_MISC:
      return "MISC";
  }
}

void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt =
      (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

//   if (ipkt->hdr.addr2[0] == 0x34 && ipkt->hdr.addr2[1] == 0xd2 &&
//       ipkt->hdr.addr2[2] == 0x70 && ipkt->hdr.addr2[3] == 0x3a &&
//       ipkt->hdr.addr2[4] == 0xfa && ipkt->hdr.addr2[5] == 0xb5) {
//     printf(
//         "PACKET TYPE=%s, CHAN=%02d, RSSI=%02d,"
//         " ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
//         " ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
//         " ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",
//         wifi_sniffer_packet_type2str(type), ppkt->rx_ctrl.channel,
//         ppkt->rx_ctrl.rssi,
//         /* ADDR1 */
//         hdr->addr1[0], hdr->addr1[1], hdr->addr1[2], hdr->addr1[3],
//         hdr->addr1[4], hdr->addr1[5],
//         /* ADDR2 */
//         hdr->addr2[0], hdr->addr2[1], hdr->addr2[2], hdr->addr2[3],
//         hdr->addr2[4], hdr->addr2[5],
//         /* ADDR3 */
//         hdr->addr3[0], hdr->addr3[1], hdr->addr3[2], hdr->addr3[3],
//         hdr->addr3[4], hdr->addr3[5]);
//   }

  //   if (ipkt->hdr.addr2[0] == 0xb4 && ipkt->hdr.addr2[1] == 0x7c &&
  //       ipkt->hdr.addr2[2] == 0x9c && ipkt->hdr.addr2[3] == 0xae &&
  //       ipkt->hdr.addr2[4] == 0xad && ipkt->hdr.addr2[5] == 0xe7) {
  //     printf("frame_ctrl=%04x\n", hdr->frame_ctrl);
  //     if (((hdr->frame_ctrl & 0x00f0) >> 4) == 0x04) {
  //       printf(
  //           "PACKET TYPE=%s, CHAN=%02d, RSSI=%02d,"
  //           " ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
  //           " ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
  //           " ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",
  //           wifi_sniffer_packet_type2str(type), ppkt->rx_ctrl.channel,
  //           ppkt->rx_ctrl.rssi,
  //           /* ADDR1 */
  //           hdr->addr1[0], hdr->addr1[1], hdr->addr1[2], hdr->addr1[3],
  //           hdr->addr1[4], hdr->addr1[5],
  //           /* ADDR2 */
  //           hdr->addr2[0], hdr->addr2[1], hdr->addr2[2], hdr->addr2[3],
  //           hdr->addr2[4], hdr->addr2[5],
  //           /* ADDR3 */
  //           hdr->addr3[0], hdr->addr3[1], hdr->addr3[2], hdr->addr3[3],
  //           hdr->addr3[4], hdr->addr3[5]);
  //     }
  //   }
}
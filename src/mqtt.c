#include <stdlib.h>
#include <string.h>
#include "mqtt.h"
#include "pack.h"

// Remaining length field on the fixed header can be at most 4 bytes.
static const int MAX_LEN_BYTES = 4;

static size_t unpack_mqtt_connect(const unsigned char *, union mqtt_header *, union mqtt_packet *);
static size_t unpack_mqtt_publish(const unsigned char *, union mqtt_header *, union mqtt_packet *);
static size_t unpack_mqtt_subscribe(const unsigned char *, union mqtt_header *, union mqtt_packet *);
static size_t unpack_mqtt_unsubscribe(const unsigned char *, union mqtt_header *, union mqtt_packet *);
static size_t unpack_mqtt_ack(const unsigned char *, union mqtt_header *, union mqtt_packet *);

static unsigned char *pack_mqtt_header(const union mqtt_header *);
static unsigned char *pack_mqtt_ack(const union mqtt_packet *);
static unsigned char *pack_mqtt_connack(const union mqtt_packet *);
static unsigned char *pack_mqtt_suback(const union mqtt_packet *);
static unsigned char *pack_mqtt_publish(const union mqtt_packet *);

/**
 * Encoding of remaining length on a MQTT packet header
 *
 * @see https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/errata01/os/mqtt-v3.1.1-errata01-os-complete.html#_Toc442180836
 */
int mqtt_encode_length(unsigned char *buf, size_t len) {
    int bytes = 0;

    do {
        if (bytes + 1 > MAX_LEN_BYTES) {
            return bytes;
        }

        short encodedByte = len % 128;
        len /= 128;

        // if there are more data to encode, set the top bit of this byte
        if (len > 0) {
            encodedByte |= 128;
        }
        buf[bytes++] = encodedByte;
    } while (len > 0);

    return bytes;
}

/**
 * Decoding of remaining length on a MQTT packet header
 *
 * @see https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/errata01/os/mqtt-v3.1.1-errata01-os-complete.html#_Toc442180836
 */
 unsigned long long mqtt_decode_length(const unsigned char **buf) {
     char c;
     int multiplier = 1;
     unsigned long long value = 0LL;
    do {
        c = **buf;
        value += (c & 127) * multiplier;
        multiplier *= 128;

        (*buf)++;
    } while ((c & 128) != 0);

    return value;
 }
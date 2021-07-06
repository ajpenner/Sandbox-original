#include "ads1248.h"

struct ads1248_options_t {
    uint32_t pin_reset;
    uint32_t pin_drdy;
    uint32_t pin_start;
    volatile avr32_spi_t *spi_module;
    uint8_t cs_id;  
};

ads1248_options_t* ads1248_init ()
{
  ads1248_options_t* ads = malloc(sizeof(ads1248_options_t));
  ads->pin_reset = 9;
  ads->pin_drdy = 8;
  ads->pin_start = 7;
  ads->cs_id = 6;
  // do things with ads based on parameters
  return ads;
}

void ads1248_destroy (ads1248_options_t* ads)
{
  free(ads);
}

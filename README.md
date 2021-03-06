# ipcheck

IPCheck - Proxy Checker

* Live at https://tools.wmflabs.org/ipcheck/
* Development staging at https://tools.wmflabs.org/ipcheck-dev/

## Installation

Requires PHP 7.2.

1. `cp credentials.php.dist credentials.php` and fill in your API keys.
1. `cp webhostconfig.php.dist webhostconfig.php` and fill in your webhost detection settings.
1. `cp oauth.ini.dist oauth.ini` and fill in your OAuth consumer keys.
1. `cp config.dist.php config.php` and change the configuration to your liking.
1. `composer install`
1. `cd public_html && php -S localhost:8000`

You should now be up and running at http://localhost:8000

## Interpreting results

* There are some tips / hints at [EXPLANATION.md](EXPLANATION.md)
  * Please don't hesitate to send a pull request for this file!

## API

* Instructions on using the API can be found at [API.MD](API.MD)

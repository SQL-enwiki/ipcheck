# API Usage

* Get paramaters:
  * ip - The IP Address
  * api - Set to true if using the API
  * key - Your personal API key (found at the bottom of the page after logging in)
  * Example URL: https://tools.wmflabs.org/ipcheck-dev/index.php?ip=8.8.8.8&api=true&key=APIKEYHERE
  
Example result:
```javascript
{
  "proxycheck": {
    "title": "proxycheck.io",
    "result": {
      "proxy": false
    }
  },
  "getIPIntel": {
    "title": "GetIPIntel",
    "result": {
      "chance": "0.0"
    }
  },
  "ipQualityScore": {
    "title": "IPQualityScore",
    "result": {
      "proxy": true,
      "isp": "Google",
      "vpn": true,
      "mobile": false
    }
  },
  "ipHub": {
    "title": "IPHub",
    "result": {
      "isp": "GOOGLE",
      "block": 1
    }
  },
  "teohio": {
    "title": "Teoh.io",
    "result": {
      "hosting": false,
      "vpnOrProxy": true,
      "type": "business",
      "risk": "high"
    }
  },
  "ipHunter": {
    "title": "IPHunter",
    "result": {
      "isp": "Google Inc.",
      "block": 1
    }
  },
  "noFraud": {
    "title": "Nofraud",
    "result": {
      "chance": 100
    }
  },
  "computeHosts": {
    "title": "Compute Hosts",
    "result": {
      "cloud": "This IP is not an AWS/Azure/GoogleCloud node.\n"
    }
  },
  "sorbs": {
    "title": "SORBS DNSBL"
  },
  "spamhaus": {
    "title": "Spamhaus ZEN DNSBL"
  },
  "dshield": {
    "title": "DShield",
    "result": {
      "attacks": 45,
      "tfeeds": "forumspam lastseen(2018-12-05), qakbot lastseen(2015-04-03)"
    }
  },
  "hola": {
    "title": "Hola"
  },
  "cache": {
    "title": "Cache",
    "result": {
      "cached": "yes",
      "cachedate": "Feb 4 19:26:17 UTC 2019",
      "cacheuntil": "Feb 11 19:26:17 UTC 2019"
    }
  }
}
```

#Notes

* Misusing, or overusing the API is grounds for a ban
  * We have finite resources, please don't take more than your share.

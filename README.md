Opauth-LINE
=============
[Opauth][1] strategy for LINE.

Implemented based on https://developers.line.me/web-api/integrating-web-login-v2 using OAuth2.

Opauth is a multi-provider authentication framework for PHP.

Getting started
----------------
1. Install Opauth-LINE:
   ```bash
   cd path_to_opauth/Strategy
   git clone git://github.com/pastatsh/opauth-line.git LINE
   ```

2. Create a server-side application at https://business.line.me/
   - Callback URL: enter `http://path_to_opauth/line/oauth2callback`

   
3. Configure Opauth-LINE strategy.

4. Direct user to `http://path_to_opauth/line` to authenticate


Strategy configuration
----------------------

Required parameters:

```php
<?php
'LINE' => array(
	'channel_id' => 'YOUR CHANNEL ID',
	'channel_secret' => 'YOUR CHANNEL SECRET'
)
```

Optional parameters:
`state`


License
---------
Opauth-LINE is MIT Licensed  
Copyright © 2017 pastatsh (https://github.com/pastatsh)

[1]: https://github.com/uzyn/opauth
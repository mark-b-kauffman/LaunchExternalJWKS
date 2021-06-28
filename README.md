# BBDN-LaunchExternal

This project is set up to demonstrate the use of LTI 1.3 in Python to replace launch_external.jsp functionality.

To configure:

## app/lti.json, app/private.key, and app/Config.py

This [document](https://docs.blackboard.com/standards/lti/tutorials/py-lti-1p3) shows how to configure the PyLTI1.3 library, which is done through the `configs`directory. The specifics for this code are given in the lti-template.json/lti.json instructions following. (In the tutorial document the file name is game.json.)

## ConfigTemplate.py

Copy `ConfigTemplate.py` to `Config.py` and fill in your information:
```
config = {
    "verify_certs" : "True",
    "learn_rest_url" : "YOURLEARNSERVERNOHTTPS",
    "learn_rest_key" : "YOURLEARNRESTKEY",
    "learn_rest_secret" : "YOURLEARNRESTSECRET",
    "app_url" : "YOURAPPURLWITHHTTPS"
}
```
* **learn_rest_url** should be set to your learn instances domain. Be sure to avoid the request scheme, i.e. `mylearn.blackboard.edu`
* **app_url** should be set to the FQDN of your application, i.e. `https://myapp.herokuapp.com`
## lti-template.json
Copy `lti-template.json` to `lti.json` and fill in your information. 
Example - Replace the fffa0f... values with your client_id, and the deployment id value with the deployment id you get when
you deploy your tool on a learn system. This tool is currently built so that it only works with exactly one Learn instance:
```
{
    "https://blackboard.com": {
        "client_id": "fffa0f2c-e86f-46fb-a330-9bc94f994ab7",
        "auth_login_url": "https://developer.blackboard.com/api/v1/gateway/oidcauth",
        "auth_token_url": "https://developer.blackboard.com/api/v1/gateway/oauth2/jwttoken",
        "key_set_url": "https://developer.blackboard.com/api/v1/management/applications/fffa0f2c-e86f-46fb-a330-9bc94f994ab7/jwks.json",
        "key_set": null,
        "private_key_file": "private.key",
	    "public_key_file": "public.key",
        "deployment_ids": ["8848b618-14e0-4965-89c1-42d4be72ec48"]
    }
}
```

In the app directory you also need to generate your tool's private.key and public.key files that are in the app directory:
```
openssl genrsa -out private.key 2048
openssl rsa -in private.key -pubout -out public.key
```

## To Run

First run `pip install -r requirements.txt`  and then `python app.py` or if you are using heroku, just check in the code to your dyno.

OR
Use the included Dockerfile and the following. The assumption is that you have Docker desktop an ngrok on your development system.

Start your ngrok tunnel. Example:
$ ngrok http -region=us -hostname=launchexternal.ngrok.io 5000
Build the Docker image. Note the period at the end.
$ docker build -t launch-external:0.1 .
Now run it. From the terminal, type:
$ docker run -p 5000:5000 --rm --name LaunchExternal launch-external:0.1

NOTE: When you host this LTI application on a remote server the app MUST have it's own unique subdomain. I.E. you must use something like https://launchexternal.myschool.edu/ or https://launchexternal.apps.myschool.edu/ as the root path to the tool. Per the LTI specification you can NOT use https://myschoolapps.myschool.edu/launchexternal/ where launchexternal is one of the many apps you have under the root.

## On your Learn server
Register the LTI 1.3 tool with your client_id.
Create a "Course content tool" managed placment for the URL you want to launch to with a custom parameter external_url= to where you want to launch.
Example:
```
    Label: Foodies With User Name
    Handle: foodieswithusername
    Course content tool
    Target Link URI: https://launchexternal.ngrok.io/launch/
    Custom Parameters: external_url=https://www.foodies.com?user%3D@X@user.id@X@
```

Note that the url will be escaped by Learn to be:external_url=https://www.foodies.com?user=@X@user.id@X@
You need to input the = sign after user as %3D, because Learn will not accept an = there as it thinks that is another custom parameter. I.E. You input external_url=https://www.foodies.com?user%3D@X@user.id@X@ and when you hit submit Learn parses that, replacing the %3D with the = sign.

You can do the same to create custom launches from system tool or administration tool links.
You can use any of the @X@ template variables described here in your launch:
https://docs.blackboard.com/learn/b2/advanced/dynamic-rendering-with-template-variables


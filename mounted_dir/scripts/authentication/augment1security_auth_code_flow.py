"""
This script can be used by the Script Based Authentication Method to perform authentication for a given context.

To use this script, select it in the Session Properties dialog -> Authentication panel.
"""
import base64, urllib, json
import java.lang.String, jarray
import org.parosproxy.paros.network.HttpRequestHeader as HttpRequestHeader
import org.parosproxy.paros.network.HttpHeader as HttpHeader
import org.apache.log4j.Logger as Logger
import org.zaproxy.zap.extension.script.ScriptVars as GlobalVariables
import net.htmlparser.jericho.Source as Source;
from org.apache.commons.httpclient import URI
from urllib import quote
from urllib import unquote
import urlparse

log = Logger.getLogger("augment1security_auth_code_flow");

def authenticate(helper, paramsValues, credentials):
    log.info("API-based authenticating via Jython script...");
    GlobalVariables.setGlobalVar("accessToken", None);
    authorizeUrl = paramsValues["authorize_url"];
    tokenUrl = paramsValues["token_url"];
    scope = paramsValues["scope"];
    redirectUri = paramsValues["redirect_uri"];
    state = paramsValues["state"];
    clientId = paramsValues["client_id"];
    clientSecret = paramsValues["client_secret"];

    authorizationCode = None;
    log.info("2) Calling GET /auth/oauth/authorize");
    authorizeQueryParameters = {'client_id':clientId, 'redirect_uri':redirectUri, 'response_type':'code', 'scope': scope, 'state': state};
    msg = callGet(helper, authorizeUrl, authorizeQueryParameters, True);
    loginUrl = msg.getResponseHeader().getHeader('Location');
    log.info("loginUrl:"+loginUrl);
    authorizationCodeList = getQueryParameterValue(loginUrl, "code")
    if len(authorizationCodeList) > 0:
        authorizationCode = authorizationCodeList[0];
        log.info("authorizationCode:"+ authorizationCode);
    else:
        log.info("No authorizationCode");

    if(authorizationCode is None):
	    log.info("3) calling GET /auth/login");
	    msg = callGet(helper, loginUrl, None, True);
	    csrfValue = getValueOfHtmlAttribute(str(msg.getResponseBody()),"input", "_csrf");
	    log.info("/auth/login csrfValue:"+str(csrfValue));
	
	    log.info("5a) calling POST /auth/login");
	    loginBodyParameters = {'username':credentials.getParam("username"), 'password':credentials.getParam("password"), '_csrf':csrfValue};
	    msg = callPost(helper, loginUrl, loginBodyParameters, "application/x-www-form-urlencoded", None);
	
	    log.info("5b) calling redirected GET /auth/oauth/authorize to get the page that allows you to select the scope");
	    redirectedAuthorizeUrl = msg.getResponseHeader().getHeader('Location');
	    log.info("redirectedAuthorizeUrl:"+str(redirectedAuthorizeUrl));
	    msg = callGet(helper, str(redirectedAuthorizeUrl), None, True);

	    csrfValue = getValueOfHtmlAttribute(str(msg.getResponseBody()),"input", "_csrf");
	    log.info("redirectedAuthorizeUrl csrfValue:"+str(csrfValue));
	    if csrfValue is None:
	        redirectedAuthorizedCodeUrl = msg.getResponseHeader().getHeader('Location');
	        log.info("redirectedAuthorizedCodeUrl:"+str(redirectedAuthorizedCodeUrl));
	        authorizationCodeList = getQueryParameterValue(str(redirectedAuthorizedCodeUrl), "code");
	        log.info("authorizationCode:"+ str(authorizationCodeList[0]));
	        authorizationCode = authorizationCodeList[0];
	    else:
	        log.info("5c) calling POST /auth/oauth/authorize with scoped permissons");
	        scopedPermissionParameters = {'user_oauth_approval':'true', 'scope.read':'true', 'scope.write':'true', 'authorize':'Authorize','_csrf':csrfValue};
	        msg = callPost(helper, authorizeUrl, scopedPermissionParameters, "application/x-www-form-urlencoded", None);
	        redirectedAuthorizedCodeUrl = msg.getResponseHeader().getHeader('Location');
	        log.info("redirectedAuthorizedCodeUrl:"+str(redirectedAuthorizedCodeUrl));
	        authorizationCodeList = getQueryParameterValue(redirectedAuthorizedCodeUrl, "code");
	        log.info("authorizationCode:"+ str(authorizationCodeList[0]));
	        authorizationCode = authorizationCodeList[0];

    log.info("7) calling token endpoint to get access token");
    getTokenParameters = {'grant_type':'authorization_code', 'code':authorizationCode, 'redirect_uri':redirectUri};
    encodedData = (clientId + ":" + clientSecret).encode('utf-8');
    authorizationHeader = "Basic " + base64.b64encode(encodedData);
    msg = callPost(helper, tokenUrl, getTokenParameters, "application/x-www-form-urlencoded", authorizationHeader);
    accessToken = json.loads(str(msg.getResponseBody()))["access_token"];
    log.info("accessToken:"+str(accessToken));

    GlobalVariables.setGlobalVar("accessToken",accessToken);
    return msg;


def getRequiredParamsNames():
	"""Obtain the name of the mandatory/required parameters needed by the script.

	This function is called during the script loading to obtain a list of the names of the required configuration parameters, that will be shown in the Session Properties -> Authentication panel for configuration. They can be used to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.)
	"""
    	return jarray.array(["authorize_url","token_url","scope","redirect_uri", "state","client_id","client_secret"], java.lang.String);


def getOptionalParamsNames():
	"""Obtain the name of the optional parameters needed by the script.

	This function is called during the script loading to obtain a list of the names of the optional configuration parameters, that will be shown in the Session Properties -> Authentication panel for configuration. They can be used to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.).
	"""
    	return jarray.array([], java.lang.String);


def getCredentialsParamsNames():
	"""Obtain the name of the credential parameters needed by the script.

	This function is called during the script loading to obtain a list of the names of the parameters that are required, as credentials, for each User configured corresponding to an Authentication using this script.
	"""
    	return jarray.array(["username", "password"], java.lang.String);

def callGet(helper, requestUrl, queryParameters, requestUrlEscaped):
    log.info("-----start of callGet-------");
    if queryParameters is not None and len(queryParameters) > 0:
        requestUrl = requestUrl + "?"
        for index, key in enumerate(queryParameters):
            log.info(str(index) +") parameter:"+ key);
            if index != 0:
                requestUrl = requestUrl + "&";
            requestUrl = requestUrl +key+"="+quote(queryParameters[key]).encode('utf-8');

    log.info("requestUrl:"+requestUrl);
    requestUri = URI(requestUrl, requestUrlEscaped);
    msg = helper.prepareMessage();
    requestHeader = HttpRequestHeader(HttpRequestHeader.GET, requestUri, HttpHeader.HTTP10);
    msg.setRequestHeader(requestHeader);
    log.info("Sending GET request: " + str(requestHeader));
    helper.sendAndReceive(msg);
    log.info("Received response status code for authentication request: " + str(msg.getResponseHeader()));
    log.info("------------------------------------");
    return msg;

def callPost(helper, requestUrl, requestBodyParameters, contentType, authorizationHeader):
    log.info("-----start of callPost ("+requestUrl+")-------");
    postBody = "";
    if requestBodyParameters is not None and len(requestBodyParameters) > 0:
        for index, key in enumerate(requestBodyParameters):
            log.info(str(index) +") parameter"+ key);
            if index != 0:
                postBody = postBody + "&";
            postBody = postBody +key+"="+quote(requestBodyParameters[key]).encode('utf-8');

    requestUri = URI(requestUrl, False);
    log.info("url encoded request body:"+postBody);
    msg = helper.prepareMessage();
    requestHeader = HttpRequestHeader(HttpRequestHeader.POST, requestUri, HttpHeader.HTTP10);
    requestHeader.setHeader("content-type",contentType);
    if authorizationHeader is not None:
        requestHeader.setHeader(HttpRequestHeader.AUTHORIZATION, authorizationHeader);

    msg.setRequestHeader(requestHeader);
    msg.setRequestBody(postBody);
    log.info("Sending POST request header: " + str(requestHeader));
    log.info("Sending POST request body: " + str(postBody));
    helper.sendAndReceive(msg);
    log.info("\nReceived response status code for authentication request: " + str(msg.getResponseHeader()));
    log.info("\nResponseBody: " + str(msg.getResponseBody()));
    log.info("------------------------------------");
    return msg;

def getQueryParameterValue(url, queryParameterName):
    log.info("getQueryParameterValue url:"+url);
    parsed = urlparse.urlparse(url);
    return urlparse.parse_qs(parsed.query).get(queryParameterName,[]);

def getValueOfHtmlAttribute(htmlText, tagName, attributeName):
    htmlSource = Source(htmlText);
    tagElements = htmlSource.getAllElements(tagName);
    attributeNameValue = None;
    for tagElement in tagElements:
        log.info("attributeNameValue:"+tagElement.getAttributeValue("name"));
        log.info(tagElement.getAttributeValue("name") == str(attributeName));
        if tagElement.getAttributeValue("name") == attributeName:
            attributeNameValue = tagElement.getAttributeValue("value");
            log.info("found attributeNameValue:" +str(attributeNameValue));

    return attributeNameValue; 

def getLoggedInIndicator():
    return "access_token";


def getLoggedOutIndicator():
    return "unauthorized|invalid_token";

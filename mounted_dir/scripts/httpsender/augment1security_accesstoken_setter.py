# The sendingRequest and responseReceived functions will be called for all
# requests/responses sent/received by ZAP, including automated tools (e.g.
# active scanner, fuzzer, ...)

# Note that new HttpSender scripts will initially be disabled
# Right click the script in the Scripts tree and select "enable"

# 'initiator' is the component the initiated the request:
#      1   PROXY_INITIATOR
#      2   ACTIVE_SCANNER_INITIATOR
#      3   SPIDER_INITIATOR
#      4   FUZZER_INITIATOR
#      5   AUTHENTICATION_INITIATOR
#      6   MANUAL_REQUEST_INITIATOR
#      7   CHECK_FOR_UPDATES_INITIATOR
#      8   BEAN_SHELL_INITIATOR
#      9   ACCESS_CONTROL_SCANNER_INITIATOR
#     10   AJAX_SPIDER_INITIATOR
# For the latest list of values see the HttpSender class:
# https://github.com/zaproxy/zaproxy/blob/master/src/org/parosproxy/paros/network/HttpSender.java
# 'helper' just has one method at the moment: helper.getHttpSender() which
# returns the HttpSender instance used to send the request.
#
# New requests can be made like this:
# msg2 = msg.cloneAll() # msg2 can then be safely changed without affecting msg
# helper.getHttpSender().sendAndReceive(msg2, false)
# print('msg2 response code =' + msg2.getResponseHeader().getStatusCode())
import org.parosproxy.paros.network.HtmlParameter as HtmlParameter
import org.zaproxy.zap.extension.script.ScriptVars as GlobalVariables
import urlparse
from org.apache.commons.httpclient import URI
import org.apache.log4j.Logger as Logger

log = Logger.getLogger("augment1security_accesstoken_setter");

def sendingRequest(msg, initiator, helper):
    log.info('HTTPSENDER sendingRequest called for url=' +msg.getRequestHeader().getURI().toString());
    if GlobalVariables.getGlobalVar("accessToken") is None:
        log.info("There is no accessToken global var, do nothing");
        return
    else:
         accessToken = GlobalVariables.getGlobalVar("accessToken");
         log.info("HTTPSENDER accessToken:"+accessToken);
         uri = msg.getRequestHeader().getURI().toString();
         newUri = uri;             
         parsedUri = urlparse.urlparse(uri);
         urlParametersList = urlparse.parse_qs(parsedUri.query);
         log.info("HTTPSENDER number of existing parameters:"+str(len(urlParametersList)));
         # if there are existing query parameters, we append '&' or else access_token is the only query parameter
         if len(urlParametersList) > 0:
             newUri = newUri + "&";
         else:
             newUri = newUri + "?";
         newUri = newUri +"access_token="+ accessToken;
         msg.getRequestHeader().setURI(URI(newUri, True));
         urlParams = msg.getUrlParams();
         for urlParam in urlParams:
             log.info("HTTPSENDER urlParam:"+urlParam.getName()+":"+urlParam.getValue());
         log.info('HTTPSENDER Adding token to request url=' + msg.getRequestHeader().getURI().toString());         
         return



def responseReceived(msg, initiator, helper):
    # Debugging can be done using print like this
    log.info('responseReceived called for url=' +
          msg.getRequestHeader().getURI().toString())

const axios = require('axios');

const url = process.env.OPA_HOST;
const routeAuth = '/v1/data/backloops/access';
const fullRouteAuth = url + routeAuth;
const serviceName = process.env.SERVICE_NAME;

function formatRequest(request, additionalData = {}) {
    req = {
        headers: request.headers || {},
        method: request.method|| '',
        protocol: `HTTP/${request.httpVersion || ''}`,
        host: request.headers ? request.headers.host || '' : '',
        path: request._url ? request._url.pathname || '' : '',
        query: request._url ? request._url.query || '' : '',
        service: serviceName || ''
    };
    return {
        input : {
            request : req,
            data: additionalData
        }
    };
}

async function getOpaAuth(request, additionalData = {}) {
    const res = await axios.post(fullRouteAuth,formatRequest(request, additionalData));
    if (res.status != 200) {
        console.log('status code KO');
        return null;
    }
    return res.data;
}
async function isAuthorized(request, targetUserIDs, additionalData = {}) {
    if (request._tokendata) {
        if (request._tokendata.isserver) {
            return true;
        }
        if (targetUserIDs.length == 1 && request._tokendata.userid == targetUserIDs[0]) {
            return true;
        }
        try {
            res = await getOpaAuth(request, additionalData)
            if (res && res.result) {
                return Boolean(res.result.authorized)
            }
        } catch (error) {
            console.error(error);
            console.log(`Error during request ${error}`);
            return false;
        }
    }
    return false;
}
module.exports = {
    isAuthorized: isAuthorized
};

/*
 * == BSD2 LICENSE ==
 * Copyright (c) 2014, Tidepool Project
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the associated License, which is identical to the BSD 2-Clause
 * License as published by the Open Source Initiative at opensource.org.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the License for more details.
 * 
 * You should have received a copy of the License along with this program; if
 * not, you can obtain one from Tidepool Project at tidepool.org.
 * == BSD2 LICENSE ==
 */

const sinon = require('sinon');
const expect = require('chai').expect;
const axios = require('axios');

describe('Opa client', function() {
  const opaHost = 'http://my-opa'
  const serviceName = 'test-service'
  const stubs = {
    host : sinon.stub(process.env, 'OPA_HOST').value(opaHost),
    service : sinon.stub(process.env, 'SERVICE_NAME').value(serviceName)
  };
  const client = require('../lib').opaClient;
  
  const initStub = (response={}) => {
    stubs.axios = sinon.stub(axios, 'post').returns(response);
  };

  const userId1 = "1234"
  const userId2 = `${userId1}_bis`
  const requests = {
    serverToken : {
      _tokendata: {
        isserver: true
      }
    },
    self : {
      _tokendata: {
        userid: userId1,
      }
    },
    restifyReq : {
      _tokendata: {
        userid: userId1,
      },
      headers: {
        host: "http://test",
        "custom-header": "test"
      },
      method: "TEST",
      httpVersion: "1.5",
      _url: {
        pathname: "/route/subroute",
        query: "var1=2&var2=2"
      }
    }
  }
  const expectedRestifyRequest = {
    input : {
        request : {
          headers: requests.restifyReq.headers,
          method: requests.restifyReq.method,
          protocol: `HTTP/${requests.restifyReq.httpVersion}`,
          host: requests.restifyReq.headers.host,
          path: requests.restifyReq._url.pathname,
          query: requests.restifyReq._url.query,
          service: serviceName
        },
        data: {}
    }
  }

  after(function() {
    stubs.host.restore();
    stubs.service.restore();
  });

  afterEach(function() {
    stubs.axios.restore();
  });
  describe('Teams authorization', function() {
    it('Requests without token data should not be authorized', async function() {
      initStub();
      const auth = await client.isAuthorized({})
      expect(auth).to.equal(false);
      expect(stubs.axios.called).to.equal(false);
    });

    it('Requests with server token should be authorized', async function() {
      initStub();
      const auth = await client.isAuthorized(requests.serverToken)
      expect(auth).to.equal(true);
      expect(stubs.axios.called).to.equal(false);
    });

    it('Requests for self should be authorized', async function() {
      initStub();
      const auth = await client.isAuthorized(requests.self,[userId1])
      expect(auth).to.equal(true);
      expect(stubs.axios.called).to.equal(false);
    });

    it('Requests for other user should call teamsApi', async function() {
      initStub({});
      const auth = await client.isAuthorized(requests.self,[userId1, userId2]);
      expect(auth).to.equal(false);
      expect(stubs.axios.called).to.equal(true);
      const expectedRequest = {
        input : {
            request : {
              headers: {},
              method: '',
              protocol: 'HTTP/',
              host: '',
              path: '',
              query: '',
              service: serviceName
            },
            data: {}
        }
      }
      sinon.assert.calledWith(stubs.axios, 
        opaHost+'/v1/data/backloops/access',expectedRequest
      );
    });

    it('Requests for other user should call teamsApi and forward source request data', async function() {
      initStub({});
      const auth = await client.isAuthorized(requests.restifyReq,[userId1, userId2])
      expect(auth).to.equal(false);
      expect(stubs.axios.called).to.equal(true);
      sinon.assert.calledWith(stubs.axios, 
        opaHost+'/v1/data/backloops/access',expectedRestifyRequest
      );
    });

    it('Requests for other user should call teamsApi and forward additional data', async function() {
      initStub({});
      const auth = await client.isAuthorized(requests.restifyReq,[userId1, userId2],{test:"test0"})
      expect(auth).to.equal(false);
      expect(stubs.axios.called).to.equal(true);
      const expectedRequest = {...expectedRestifyRequest}
      expectedRequest.input.data = {test:"test0"}
      sinon.assert.calledWith(stubs.axios, 
        opaHost+'/v1/data/backloops/access',expectedRequest
      );
    });

    it('Requests for other user should call teamsApi and return authorized result when status is 200', async function() {
      initStub({status:200, data:{result:{authorized:true}}});
      const auth = await client.isAuthorized(requests.restifyReq,[userId1, userId2]);
      expect(stubs.axios.called).to.equal(true);
      expect(auth).to.equal(true);
    });

    it('Requests for other user should call teamsApi and return false when status is not 200', async function() {
      initStub({status:404, data:{result:{authorized:true}}});
      const auth = await client.isAuthorized(requests.restifyReq,[userId1, userId2]);
      expect(auth).to.equal(false);
      expect(stubs.axios.called).to.equal(true);
    });
  });

  
  describe('Self authorization',function() {
    it('Requests without token data  should not be authorized',  function() {
      const auth = client.selfAuthorized({},[userId1]);
      expect(auth).to.equal(false);
    });

    it('Requests with token userId exactly matching target userIDs should be authorized', function() {
      const auth = client.selfAuthorized(requests.self,[userId1]);
      expect(auth).to.equal(true);
    });

    it('Requests with token userId not exactly matching target userIDs should not be authorized', function() {
      const auth = client.selfAuthorized(requests.self,[userId1, userId2]);
      expect(auth).to.equal(false);
    });

    it('Requests with token userId not matching target userIDs should not be authorized', function() {
      const auth = client.selfAuthorized(requests.self,[ userId2]);
      expect(auth).to.equal(false);
    });

    it('Requests with server token should be authorized',  function() {
      let auth = client.selfAuthorized(requests.serverToken,[userId2]);
      expect(auth).to.equal(true);
      auth = client.selfAuthorized(requests.serverToken,[userId1, userId2]);
      expect(auth).to.equal(true);
    });
  });
  describe('Server authorization',function() {
    it('Requests with server token should be authorized',  function() {
      let auth = client.serverAuthorized(requests.serverToken,[userId2]);
      expect(auth).to.equal(true);
      auth = client.serverAuthorized(requests.serverToken,[userId1, userId2]);
      expect(auth).to.equal(true);
    });

    it('Requests with user token should not be authorized',  function() {
      const auth = client.serverAuthorized(requests.self,[userId1]);
      expect(auth).to.equal(false);
    });
  });
})

package com.stephen.apps.samples.springauthjwt.models

class AuthenticationRequest(
    var username: String = "",
    var password: String = ""
)

class AuthenticationResponse(
    var jwt: String
)

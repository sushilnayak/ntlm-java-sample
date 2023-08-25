package com.nayak.springbootntlmsample.controller;

import jcifs.ntlmssp.Type3Message;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/rest/ntlm")
class NtlmController {

    @GetMapping
    public void ntlmAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
        String auth = httpServletRequest.getHeader("Authorization");
        if (auth == null) {
            httpServletResponse.setStatus(401);
            httpServletResponse.setHeader("WWW-Authenticate", "NTLM");
            return;
        }
        if (auth.startsWith("NTLM ")) {
            byte[] msg = new sun.misc.BASE64Decoder().decodeBuffer(auth.substring(5));
            if (msg[8] == 1) {
                byte z = 0;
                byte[] msg1 = {(byte) 'N', (byte) 'T', (byte) 'L', (byte) 'M', (byte) 'S', (byte) 'S', (byte) 'P',
                        z, (byte) 2, z, z, z, z, z, z, z, (byte) 40, z, z, z, (byte) 1, (byte) 130, z, z, z,
                        (byte) 2, (byte) 2, (byte) 2, z, z, z, z, z, z, z, z, z, z, z, z};
                httpServletResponse.setHeader("WWW-Authenticate", "NTLM " + new sun.misc.BASE64Encoder().encodeBuffer(msg1));
                httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            } else if (msg[8] == 3) {
                Type3Message type3Message = new Type3Message(msg);
                httpServletResponse.setStatus(HttpServletResponse.SC_OK);
                httpServletResponse.setHeader("Content-Type", "application/json");
                httpServletResponse.getWriter().println("{\"domain\" : \"" + type3Message.getDomain() + "\" , \"username\":\"" + type3Message.getUser() + "\" }");

            }
        }
    }
}

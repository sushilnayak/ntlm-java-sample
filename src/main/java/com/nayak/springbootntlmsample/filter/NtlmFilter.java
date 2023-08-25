package com.nayak.springbootntlmsample.filter;

import jcifs.ntlmssp.Type3Message;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class NtlmFilter extends OncePerRequestFilter {

    @Override
    protected boolean shouldNotFilter(HttpServletRequest servletRequest) throws ServletException {
        String path = servletRequest.getServletPath();
        return !path.startsWith("/filter/ntlm");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String origin = request.getHeader("Origin");
        if (origin != null) {
            response.addHeader("Access-Control-Allow-Origin", origin);
        } else {
            response.addHeader("Access-Control-Allow-Origin", "*");
        }
        response.addHeader("Access-Control-Allow-Credentials", "true");
        response.addHeader("Access-Control-Allow-Methods", "GET, OPTIONS, HEAD, PUT, POST");

        if (request.getMethod().equals("OPTIONS")) {
            response.setStatus(HttpServletResponse.SC_ACCEPTED);
            return;
        }
        String auth = request.getHeader("Authorization");
        if (auth == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setHeader("WWW-Authenticate", "NTLM");
            return;
        }
        if (auth.startsWith("NTLM ")) {
            byte[] msg = new BASE64Decoder().decodeBuffer(auth.substring(5));
            int off = 0;
            if (msg[8] == 1) {

                byte z = 0;
                byte[] msg1 = {(byte) 'N', (byte) 'T', (byte) 'L', (byte) 'M', (byte) 'S', (byte) 'S', (byte) 'P',
                        z, (byte) 2, z, z, z, z, z, z, z, (byte) 40, z, z, z, (byte) 1, (byte) 130, z, z, z,
                        (byte) 2, (byte) 2, (byte) 2, z, z, z, z, z, z, z, z, z, z, z, z};

                String challenge = "NTLM " + new BASE64Encoder().encodeBuffer(msg1).trim();
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setHeader("WWW-Authenticate", challenge);
                return;
            } else if (msg[8] == 3) {
                off = 30;
            } else {
                return;
            }

            Type3Message type3Message = new Type3Message(msg);
            response.setStatus(HttpServletResponse.SC_OK);
            response.setHeader("Content-Type", "application/json");
            response.getWriter().println("{\"domain\" : \"" + type3Message.getDomain() + "\" , \"username\":\"" + type3Message.getUser() + "\" }");

        }
    }

}

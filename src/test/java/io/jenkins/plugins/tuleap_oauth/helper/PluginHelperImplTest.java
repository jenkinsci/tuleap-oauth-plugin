package io.jenkins.plugins.tuleap_oauth.helper;

import okhttp3.Response;
import okhttp3.ResponseBody;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class PluginHelperImplTest {

    @Test
    public void testItShouldReturnARandomStringInBase64() {
        final PluginHelperImpl codeBuilder = new PluginHelperImpl();
        final String result1 = codeBuilder.buildRandomBase64EncodedURLSafeString();
        final String result2 = codeBuilder.buildRandomBase64EncodedURLSafeString();

        assertTrue(Base64.isBase64(result1));
        assertTrue(Base64.isBase64(result2));
        assertNotEquals(result1, result2);
    }

    @Test
    public void itShouldGenerateA43BytesLongSequence() {
        final PluginHelperImpl codeBuilder = new PluginHelperImpl();

        assertEquals(43, codeBuilder.buildRandomBase64EncodedURLSafeString().getBytes().length);
    }

    @Test
    public void testItShouldReturnsFalseIfTheUriIsNotHttps() {
        final PluginHelperImpl pluginHelper = new PluginHelperImpl();

        assertFalse(pluginHelper.isHttpsUrl("http://tuleap.example.com"));
        assertFalse(pluginHelper.isHttpsUrl("ftp://tuleap.example.com"));
        assertFalse(pluginHelper.isHttpsUrl("dfkgd,nig://tuleap.example.com"));
        assertFalse(pluginHelper.isHttpsUrl("tuleap.example.com"));
    }

    @Test
    public void testItShouldReturnsTrueIfTheUriIsHttps() {
        final PluginHelperImpl pluginHelper = new PluginHelperImpl();

        assertTrue(pluginHelper.isHttpsUrl("https://tuleap.example.com"));
    }

    @Test
    public void testItShouldReturnsNullIfTheResponseHasNoBody() throws IOException {
        final PluginHelperImpl pluginHelper = new PluginHelperImpl();
        Response response = mock(Response.class);
        when(response.isSuccessful()).thenReturn(false);

        ResponseBody responseBody = mock(ResponseBody.class);
        when(response.body()).thenReturn(null);

        assertNull(pluginHelper.getResponseBody(response));
        verify(responseBody,never()).string();
    }

    @Test
    public void testItShouldReturnsNullIfTheResponseIsNotSuccessful() throws IOException {
        final PluginHelperImpl pluginHelper = new PluginHelperImpl();
        Response response = mock(Response.class);
        when(response.isSuccessful()).thenReturn(false);

        ResponseBody responseBody = mock(ResponseBody.class);
        when(response.body()).thenReturn(responseBody);
        when(responseBody.string()).thenReturn("error");

        assertNull(pluginHelper.getResponseBody(response));
    }
}

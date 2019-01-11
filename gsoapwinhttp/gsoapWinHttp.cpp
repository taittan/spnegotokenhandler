/*
See the header file for details. This file is distributed under the MIT licence.
*/

/* system */
#include <windows.h>
#include <crtdbg.h>
#include <Winhttp.h>

/* gsoap */
#include <stdsoap2.h>

/* local */
#include "gsoapWinHttp.h"

/* ensure that the winhttp library is linked */
#pragma comment( lib, "winhttp.lib" )
/* disable deprecation warnings */
#pragma warning(disable : 4996)

#define UNUSED_ARG(x)           (x)
#define INVALID_BUFFER_LENGTH  ((DWORD)-1)

/* plugin id */
static const char winhttp_id[] = "winhttp-1.0";

/* plugin private data */
struct winhttp_data
{
    HINTERNET            hInternet;          /* internet session handle */
    HINTERNET            hConnection;        /* current connection handle */
    BOOL                 bDisconnect;        /* connection is disconnected */
    DWORD                dwRequestFlags;     /* extra request flags from user */
    char *               pBuffer;            /* send buffer */
    size_t               uiBufferLenMax;     /* total length of the message */
    size_t               uiBufferLen;        /* length of data in buffer */
    BOOL                 bIsChunkSize;       /* expecting a chunk size buffer */
	char *               proxy_user;         /* optional parameter: user name for local proxy */
	char *               proxy_pass;         /* optional parameter: password for local proxy */
#ifdef SOAP_DEBUG
    /* this is only used for DBGLOG output */
    char *              pszErrorMessage;    /* winhttp/system error message */
#endif
};

/* forward declarations */
static BOOL
winhttp_init(
    struct soap *           soap, 
    struct winhttp_data *   a_pData,
    DWORD                   a_dwRequestFlags );
static int  
winhttp_copy( 
    struct soap *           soap, 
    struct soap_plugin *    a_pDst, 
    struct soap_plugin *    a_pSrc );
static void 
winhttp_delete( 
    struct soap *           soap, 
    struct soap_plugin *    a_pPluginData );
static SOAP_SOCKET  
winhttp_connect( 
    struct soap *   soap, 
    const char *    a_pszEndpoint, 
    const char *    a_pszHost, 
    int             a_nPort );
static int 
winhttp_post_header(
    struct soap *   soap, 
    const char *    a_pszKey, 
    const char *    a_pszValue );
static int 
winhttp_fsend( 
    struct soap *   soap, 
    const char *    a_pBuffer, 
    size_t          a_uiBufferLen );
static size_t 
winhttp_frecv(
    struct soap *   soap, 
    char *          a_pBuffer, 
    size_t          a_uiBufferLen );
static int 
winhttp_disconnect( 
    struct soap *   soap );
static BOOL
winhttp_have_connection(
    struct soap *           soap,
    struct winhttp_data *   a_pData );
static DWORD
winhttp_set_timeout(
    struct soap *           soap, 
    struct winhttp_data *   a_pData,
    const char *            a_pszTimeout,
    DWORD                   a_dwOption,
    int                     a_nTimeout );

#ifdef SOAP_DEBUG
/* this is only used for DBGLOG output */
static const char *
winhttp_error_message(
    struct soap *   a_pData,
    DWORD           a_dwErrorMsgId );
static void
winhttp_free_error_message(
    struct winhttp_data *   a_pData );
#else
#define winhttp_free_error_message(x)
#endif


/* plugin registration */
int 
winhttp_plugin( 
    struct soap *           soap, 
    struct soap_plugin *    a_pPluginData, 
    void *                  a_dwRequestFlags )
{
    DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
        "winhttp %p: plugin registration\n", soap ));

    a_pPluginData->id        = winhttp_id;
    a_pPluginData->fcopy     = winhttp_copy;
    a_pPluginData->fdelete   = winhttp_delete;
    a_pPluginData->data      = (void*) malloc( sizeof(struct winhttp_data) );
    if ( !a_pPluginData->data )
    {
        return SOAP_EOM;
    }
    if ( !winhttp_init( soap, 
        (struct winhttp_data *) a_pPluginData->data, 
        (DWORD) (size_t) a_dwRequestFlags ) )
    {
        free( a_pPluginData->data );
        return SOAP_EOM;
    }

#ifdef SOAP_DEBUG
    if ( (soap->omode & SOAP_IO) == SOAP_IO_STORE )
    {
        DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
            "winhttp %p: use of SOAP_IO_STORE is not recommended\n", soap ));
    }
#endif

    return SOAP_OK;
}

/* initialize private data */
static BOOL
winhttp_init(
    struct soap *           soap, 
    struct winhttp_data *   a_pData,
    DWORD                   a_dwRequestFlags )
{
    DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
        "winhttp %p: init private data\n", soap ));

    memset( a_pData, 0, sizeof(struct winhttp_data) );
    a_pData->dwRequestFlags = a_dwRequestFlags;

    /* start our internet session */
    a_pData->hInternet = WinHttpOpen(L"gSOAP", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 );
    if ( !a_pData->hInternet )
    {
        soap->error = GetLastError();
        DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
            "winhttp %p: init, error %d (%s) in InternetOpen\n", 
            soap, soap->error, winhttp_error_message(soap,soap->error) ));
        winhttp_free_error_message( a_pData );
        return FALSE;
    }

    /* set the timeouts, if any of these fail the error isn't fatal */
    winhttp_set_timeout( soap, a_pData, "connect", 
        WINHTTP_OPTION_CONNECT_TIMEOUT, soap->connect_timeout );
    winhttp_set_timeout( soap, a_pData, "receive", 
        WINHTTP_OPTION_RECEIVE_TIMEOUT, soap->recv_timeout );
    winhttp_set_timeout( soap, a_pData, "send",    
        WINHTTP_OPTION_SEND_TIMEOUT, soap->send_timeout );

    soap->fopen    = winhttp_connect;
    soap->fposthdr = winhttp_post_header;
    soap->fsend    = winhttp_fsend;
    soap->frecv    = winhttp_frecv;
    soap->fclose   = winhttp_disconnect;

    return TRUE;
}

/* Setup user name and password for proxy server */
int winhttp_set_proxy_params(struct soap* soap, const char* a_pszProxyUser, const char* a_pszProxyPsw)
{
	struct winhttp_data * pData = (struct winhttp_data *) soap_lookup_plugin( soap, winhttp_id );

	/* store proxy user name */
	if (NULL != pData->proxy_user)
		free(pData->proxy_user);
	pData->proxy_user = (char*)malloc(strlen(a_pszProxyUser)+1);
	if (NULL == pData->proxy_user)
	{
	    soap->error = SOAP_PLUGIN_ERROR;
		DBGLOG(TEST, SOAP_MESSAGE(fdebug, "winhttp error: not enough memory\n", soap));
		return SOAP_PLUGIN_ERROR;
	}
	strcpy(pData->proxy_user, a_pszProxyUser);
	/* store proxy password */
	if (NULL != pData->proxy_pass)
		free(pData->proxy_pass);
	pData->proxy_pass = (char*)malloc(strlen(a_pszProxyPsw)+1);
	if (NULL == pData->proxy_pass)
	{
	    soap->error = SOAP_PLUGIN_ERROR;
		DBGLOG(TEST, SOAP_MESSAGE(fdebug, "winhttp error: not enough memory\n", soap));
		return SOAP_PLUGIN_ERROR;
	}
	strcpy(pData->proxy_pass, a_pszProxyPsw);

    DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
        "winhttp %p: winhttp_set_proxy_params proxy_user: %s proxy_psw: %s\n",
		soap, a_pszProxyUser, a_pszProxyPsw));
	return SOAP_OK;
}


/* copy the private data structure */
static int  
winhttp_copy( 
    struct soap *           soap, 
    struct soap_plugin *    a_pDst, 
    struct soap_plugin *    a_pSrc )
{
    UNUSED_ARG( soap );
    UNUSED_ARG( a_pDst );
    UNUSED_ARG( a_pSrc );

    _ASSERTE( !"winhttp doesn't support copy" );
    return SOAP_FATAL_ERROR;
}

/* deallocate of our private structure */
static void 
winhttp_delete( 
    struct soap *           soap, 
    struct soap_plugin *    a_pPluginData )
{
    struct winhttp_data * pData = 
        (struct winhttp_data *) a_pPluginData->data;

    UNUSED_ARG( soap );

    DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
        "winhttp %p: delete private data\n", soap ));

    /* force a disconnect of any existing connection */
    pData->bDisconnect = TRUE;
    winhttp_have_connection( soap, pData );

    /* close down the internet */
    if ( pData->hInternet )
    {
        DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
            "winhttp %p: closing internet handle\n", soap));
        WinHttpCloseHandle( pData->hInternet );
        pData->hInternet = NULL;
    }
	/* free message string */
    winhttp_free_error_message( pData );
	/* free proxy params */
	if (pData->proxy_pass)
		free(pData->proxy_pass);
	pData->proxy_pass = NULL;
	if (pData->proxy_user)
		free(pData->proxy_user);
	pData->proxy_user = NULL;
	/* free our data */
    free( a_pPluginData->data );
}

/* gsoap documentation:
    Called from a client proxy to open a connection to a Web Service located 
    at endpoint. Input parameters host and port are micro-parsed from endpoint.
    Should return a valid file descriptor, or SOAP_INVALID_SOCKET and 
    soap->error set to an error code. Built-in gSOAP function: tcp_connect
*/
static SOAP_SOCKET  
winhttp_connect( 
    struct soap *   soap, 
    const char *    a_pszEndpoint, 
    const char *    a_pszHost, 
    int             a_nPort )
{
    URL_COMPONENTS  urlComponents;
    wchar_t         wUrlPath[5*MAX_PATH];
    wchar_t         wHost[5*MAX_PATH];
	wchar_t         wEndpoint[5*MAX_PATH];
    HINTERNET       hConnection  = NULL;
    HINTERNET       hHttpRequest = NULL;
    struct winhttp_data * pData = 
        (struct winhttp_data *) soap_lookup_plugin( soap, winhttp_id );

    soap->error = SOAP_OK;

    /* we parse the URL ourselves so we don't use these parameters */
    UNUSED_ARG( a_pszHost );
    UNUSED_ARG( a_nPort );

    DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
        "winhttp %p: connect, endpoint = '%s'\n", soap, a_pszEndpoint ));

    /* we should be initialized but not connected */
    _ASSERTE( pData->hInternet );
    _ASSERTE( !pData->hConnection );
    _ASSERTE( soap->socket == SOAP_INVALID_SOCKET );

    /* parse out the url path */
    memset( &urlComponents, 0, sizeof(urlComponents) );
    urlComponents.dwStructSize = sizeof(urlComponents);

	memset(wHost, 0, 5*MAX_PATH);
	memset(wUrlPath, 0, 5*MAX_PATH);
	memset(wEndpoint, 0, 5*MAX_PATH);
	mbstowcs(wEndpoint, a_pszEndpoint, strlen(a_pszEndpoint));

    urlComponents.lpszHostName      = wHost;
    urlComponents.dwHostNameLength  = MAX_PATH*4;
    urlComponents.lpszUrlPath       = wUrlPath;
    urlComponents.dwUrlPathLength   = MAX_PATH*4;
    if ( !WinHttpCrackUrl( wEndpoint, wcslen(wEndpoint), 0, &urlComponents ) )
    {
        soap->error = GetLastError();
        DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
            "winhttp %p: connect, error %d (%s) in InternetCrackUrl\n", 
            soap, soap->error, winhttp_error_message(soap,soap->error) ));
        return SOAP_INVALID_SOCKET;
    }

    /* connect to the target url, if we haven't connected yet 
       or if it was dropped */
    hConnection = WinHttpConnect( pData->hInternet, wHost, urlComponents.nPort, 0);
    if ( !hConnection )
    {
		WinHttpCloseHandle( hConnection );
        soap->error = GetLastError();
        DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
            "winhttp %p: connect, error %d (%s) in WinHttpConnect\n", 
            soap, soap->error, winhttp_error_message(soap,soap->error) ));
        return SOAP_INVALID_SOCKET;
    }
	if (INTERNET_SCHEME_HTTPS == urlComponents.nScheme)
	{ // https connection
		DWORD dwOpt = WINHTTP_FLAG_SECURE_PROTOCOL_ALL;
		if (!WinHttpSetOption(pData->hInternet, WINHTTP_OPTION_SECURE_PROTOCOLS, &dwOpt, sizeof(dwOpt)))
		{
			WinHttpCloseHandle( hConnection );
			soap->error = GetLastError();
			DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
				"winhttp %p: connect, error %d (%s) in WinHttpSetOption\n", 
				soap, soap->error, winhttp_error_message(soap,soap->error) ));
			return SOAP_INVALID_SOCKET;
		}
		hHttpRequest = WinHttpOpenRequest(hConnection, L"POST", urlComponents.lpszUrlPath, NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH|WINHTTP_FLAG_SECURE);
		if (!hHttpRequest)
		{
			WinHttpCloseHandle( hConnection );
		    soap->error = GetLastError();
			DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
				"winhttp %p: connect, error %d (%s) in WinHttpOpenRequest\n", 
				soap, soap->error, winhttp_error_message(soap,soap->error) ));
			return SOAP_INVALID_SOCKET;
		}
	}
	else if (INTERNET_SCHEME_HTTP == urlComponents.nScheme)
	{ // plain http connection
		hHttpRequest = WinHttpOpenRequest(hConnection, L"POST", urlComponents.lpszUrlPath, NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH);
		if (!hHttpRequest)
		{
			WinHttpCloseHandle( hConnection );
		    soap->error = GetLastError();
			DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
				"winhttp %p: connect, error %d (%s) in WinHttpOpenRequest\n", 
				soap, soap->error, winhttp_error_message(soap,soap->error) ));
			return SOAP_INVALID_SOCKET;
		}
	}
	
	/* pass proxy params if presents */
	if (pData->proxy_user && pData->proxy_pass)
	{
		wchar_t wcuser[_MAX_PATH];
		wchar_t wcpsw[_MAX_PATH];

		memset(wcuser, 0, _MAX_PATH);
		memset(wcpsw, 0, _MAX_PATH);
		mbstowcs(wcuser, pData->proxy_user, strlen(pData->proxy_user));
		mbstowcs(wcpsw, pData->proxy_pass, strlen(pData->proxy_pass));
		if (!WinHttpSetCredentials(hHttpRequest, WINHTTP_AUTH_TARGET_SERVER, WINHTTP_AUTH_SCHEME_BASIC,
			wcuser, wcpsw, NULL))
		{
			soap->error = GetLastError();
			DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
				"winhttp %p: connect, error %d (%s) in WinHttpSetCredentials\n", 
				soap, soap->error, winhttp_error_message(soap,soap->error) ));
			return SOAP_HTTP_ERROR;
		}
	}

    /* save the connection handle in our data structure */
    pData->hConnection = hConnection;

    /* return the http request handle as our file descriptor. */
    _ASSERTE( sizeof(soap->socket) >= sizeof(HINTERNET) );
    return (SOAP_SOCKET) hHttpRequest;
}

/* gsoap documentation:
    Called by http_post and http_response (through the callbacks). Emits HTTP 
    key: val header entries. Should return SOAP_OK, or a gSOAP error code. 
    Built-in gSOAP function: http_post_header.
 */
static int 
winhttp_post_header(
    struct soap *   soap, 
    const char *    a_pszKey, 
    const char *    a_pszValue )  
{
    HINTERNET hHttpRequest = (HINTERNET) soap->socket;
    char      szHeader[4096];
	wchar_t   wHeader[4096];
    int       nLen;
    BOOL      bResult = FALSE;
    struct winhttp_data * pData = 
        (struct winhttp_data *) soap_lookup_plugin( soap, winhttp_id );

    soap->error = SOAP_OK;

    /* ensure that our connection hasn't been disconnected */
    if ( !winhttp_have_connection( soap, pData ) )
    {
        return SOAP_EOF;
    }

    /* if this is the initial POST header then we initialize our send buffer */
    if ( a_pszKey && !a_pszValue )
    {
        _ASSERTE( !pData->pBuffer );
        pData->uiBufferLenMax = INVALID_BUFFER_LENGTH;
        pData->uiBufferLen    = 0;

        /* if we are using chunk output then we start with a chunk size */
        pData->bIsChunkSize = ( (soap->omode & SOAP_IO) == SOAP_IO_CHUNK );
    }
    else if ( a_pszValue )
    { 
        DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
            "winhttp %p: post_header, adding '%s: %s'\n", 
            soap, a_pszKey, a_pszValue ));

        /* determine the maximum length of this message so that we can
           correctly determine when we have completed the send */
        if ( !strcmp( a_pszKey, "Content-Length" ) )
        {
            _ASSERTE( pData->uiBufferLenMax == INVALID_BUFFER_LENGTH );
            pData->uiBufferLenMax = strtoul( a_pszValue, NULL, 10 );
        }

        nLen = _snprintf( 
            szHeader, 4096, "%s: %s\r\n", a_pszKey, a_pszValue );
        if ( nLen < 0 )
        {
            return SOAP_EOM;
        }
		memset( wHeader, 0, 4096*sizeof(wchar_t) );
		mbstowcs( wHeader, szHeader, strlen(szHeader));

        bResult = WinHttpAddRequestHeaders( hHttpRequest, wHeader, wcslen(wHeader), 
            WINHTTP_ADDREQ_FLAG_ADD_IF_NEW );
#ifdef SOAP_DEBUG
        /* 
            we don't return an error if this fails because it isn't 
            (or shouldn't be) critical.
         */
        if ( !bResult )
        {
            DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
                "winhttp %p: post_header, error %d (%s) in HttpAddRequestHeaders\n", 
                soap, soap->error, winhttp_error_message(soap,GetLastError()) ));
        }
#endif
    }
    return SOAP_OK; 
}

/* gsoap documentation:
    Called for all send operations to emit contents of s of length n. 
    Should return SOAP_OK, or a gSOAP error code. Built-in gSOAP 
    function: fsend

   Notes:
    I do a heap of buffering here because we need the entire message available
    in a single buffer in order to iterate through the sending loop. I had 
    hoped that the SOAP_IO_STORE flag would have worked to do the same, however
    this still breaks the messages up into blocks. Although there were a number
    of ways this could've been implemented, this works and supports all of the
    possible SOAP_IO flags, even though the entire message is still buffered 
    the same as if SOAP_IO_STORE was used.
*/
static int 
winhttp_fsend( 
    struct soap *   soap, 
    const char *    a_pBuffer, 
    size_t          a_uiBufferLen )
{
    HINTERNET   hHttpRequest = (HINTERNET) soap->socket;
    BOOL        bResult;
    BOOL        bRetryPost;
    DWORD       dwOpt;
    int         nResult = SOAP_OK;
	int resend_count_try = 5;
    struct winhttp_data * pData = 
        (struct winhttp_data *) soap_lookup_plugin( soap, winhttp_id );

    soap->error = SOAP_OK;

    DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
        "winhttp %p: fsend, data len = %lu bytes\n", soap, a_uiBufferLen ));

    /* allow the request to be sent with a NULL buffer */
    if (a_uiBufferLen == 0)
    {
        pData->uiBufferLenMax = 0;
    }

    /* ensure that our connection hasn't been disconnected */
    if ( !winhttp_have_connection( soap, pData ) )
    {
        return SOAP_EOF;
    }

    /* initialize on our first time through. pData->pBuffer will always be 
       non-null if this is not the first call. */
    if ( !pData->pBuffer )
    {
        /* 
            If we are using chunked sending, then we don't know how big the
            buffer will need to be. So we start with a 0 length buffer and
            grow it later to ensure that it is always large enough.

                uiBufferLenMax = length of the allocated memory
                uiBufferLen    = length of the data in the buffer
         */
        if ( (soap->mode & SOAP_IO) == SOAP_IO_CHUNK )
        {
            /* we make the initial allocation large enough for this chunksize 
               buffer, plus the next chunk of actual data, and a few extra 
               bytes for the final "0" chunksize block. */
            size_t uiChunkSize = strtoul( a_pBuffer, NULL, 16 );
            pData->uiBufferLenMax = uiChunkSize + a_uiBufferLen + 16;
        }
        else if ( a_uiBufferLen == pData->uiBufferLenMax )
        {
            /*  
                If the currently supplied buffer from gsoap holds the entire 
                message then we just use their buffer and avoid any memory 
                allocation. This will only be true when (1) we are not using 
                chunked send (so uiBufferLenMax has been previously set to 
                the Content-Length header length), and (2) gsoap is sending 
                the entire message at one time. 
             */
            pData->pBuffer     = (char *) a_pBuffer;
            pData->uiBufferLen = a_uiBufferLen;
        }

        _ASSERTE( pData->uiBufferLenMax != INVALID_BUFFER_LENGTH );
    }

    /*
        If we can't use the gsoap buffer, then we need to allocate our own
        buffer for the entire message. This is because authentication may 
        require the entire message to be sent multiple times. Since this send
        is only a part of the message, we need to buffer until we have the 
        entire message.
    */
    if ( pData->pBuffer != a_pBuffer )
    {
        /* 
            We already have a buffer pointer, this means that it isn't the 
            first time we have been called. We have allocated a buffer and 
            are current filling it. 
            
            If we don't have enough room in the our buffer to add this new 
            data, then we need to reallocate. This case will only occur with 
            chunked sends. 
         */
        size_t uiNewBufferLen = pData->uiBufferLen + a_uiBufferLen;
        if ( !pData->pBuffer || uiNewBufferLen > pData->uiBufferLenMax )
        {
            while ( uiNewBufferLen > pData->uiBufferLenMax )
            {
                pData->uiBufferLenMax = pData->uiBufferLenMax * 2;
            }
            pData->pBuffer = (char *) realloc( pData->pBuffer, pData->uiBufferLenMax );
            if ( !pData->pBuffer )
            {
                return SOAP_EOM;
            }
        }
        memcpy( pData->pBuffer + pData->uiBufferLen, 
            a_pBuffer, a_uiBufferLen );
        pData->uiBufferLen = uiNewBufferLen;

        /* if we are doing chunked transfers, and this is a chunk size block,
           and it is "0", then this is the last block in the transfer and we
           can set the maximum size now to continue to the actual send. */
        if ( (soap->mode & SOAP_IO) == SOAP_IO_CHUNK
             && pData->bIsChunkSize 
             && a_pBuffer[2] == '0' && !isalnum(a_pBuffer[3]) )
        {
            pData->uiBufferLenMax = pData->uiBufferLen;
        }
    }

    /* if we haven't got the entire length of the message yet, then 
       we return to gsoap and let it continue */
    if ( pData->uiBufferLen < pData->uiBufferLenMax )
    {
        /* toggle our chunk size marker if we are chunking */
        pData->bIsChunkSize = 
            ((soap->mode & SOAP_IO) == SOAP_IO_CHUNK) 
            && !pData->bIsChunkSize; 
        return SOAP_OK;
    }
    _ASSERTE( pData->uiBufferLen == pData->uiBufferLenMax );

    /* we've now got the entire message, now we can enter our sending loop */
    bRetryPost = TRUE;
    while ( bRetryPost && resend_count_try > 0)
    {
        bRetryPost = FALSE;
		resend_count_try--;

        bResult = WinHttpSendRequest( hHttpRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
			pData->pBuffer, pData->uiBufferLen, pData->uiBufferLen, (DWORD_PTR)soap);
        if ( !bResult )
        {
            soap->error = GetLastError();
            DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
                "winhttp %p: fsend, error %d (%s) in WinHttpSendRequest\n", 
                soap, soap->error, winhttp_error_message(soap,soap->error) ));

            /* see if we can handle this error, see the MSDN documentation
               for InternetErrorDlg for details */
            switch ( soap->error )
            {
            case ERROR_WINHTTP_RESEND_REQUEST:
				DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
					"winhttp %p: fsend ERROR_WINHTTP_RESEND_REQUEST, error %d has been resolved\n", 
					soap, soap->error ));
				bRetryPost = TRUE;
				soap->error = SOAP_OK;
				pData->bDisconnect = FALSE; 
				break;
            case ERROR_WINHTTP_SECURE_INVALID_CA:
            case ERROR_WINHTTP_SECURE_CERT_CN_INVALID:
            case ERROR_WINHTTP_SECURE_CERT_DATE_INVALID:
            case ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED:
			case ERROR_WINHTTP_SECURE_FAILURE:
				dwOpt = 
					SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
					SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
					SECURITY_FLAG_IGNORE_UNKNOWN_CA;
				if (!WinHttpSetOption(hHttpRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwOpt, sizeof(dwOpt)))
				{
					soap->error = GetLastError();
					DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
						"winhttp %p: connect, error %d (%s) in WinHttpSetOption\n", 
						soap, soap->error, winhttp_error_message(soap,soap->error) ));
				    if ( pData->pBuffer != a_pBuffer )
				    {
				        free( pData->pBuffer );
				    }
					pData->pBuffer     = 0;
				    pData->uiBufferLen = 0;
					pData->uiBufferLenMax = INVALID_BUFFER_LENGTH;
					return SOAP_HTTP_ERROR;
				}
				else
				{
					DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
						"winhttp %p: fsend, error %d has been resolved\n", 
						soap, soap->error ));
					bRetryPost = TRUE;
					soap->error = SOAP_OK;
					/* 
					we would have been disconnected by the error. Since we 
					are going to try again, we will automatically be 
					reconnected. Therefore we want to disregard any 
					previous disconnection messages. 
					*/
					pData->bDisconnect = FALSE; 
				}
                break;
			default:
			    if ( pData->pBuffer != a_pBuffer )
			    {
			        free( pData->pBuffer );
			    }
			    pData->pBuffer     = 0;
			    pData->uiBufferLen = 0;
				pData->uiBufferLenMax = INVALID_BUFFER_LENGTH;
				return SOAP_HTTP_ERROR;
            }
        }
    }
    /* if we have an allocated buffer then we can deallocate it now */
    if ( pData->pBuffer != a_pBuffer )
    {
        free( pData->pBuffer );
    }

    pData->pBuffer     = 0;
    pData->uiBufferLen = 0;
    pData->uiBufferLenMax = INVALID_BUFFER_LENGTH;

	if (resend_count_try > 0)
	{
		if ( !WinHttpReceiveResponse(hHttpRequest, NULL) )
		{
			soap->error = GetLastError();
			DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
				"winhttp %p: connect, error %d (%s) in WinHttpReceiveResponse\n", 
				soap, soap->error, winhttp_error_message(soap,soap->error) ));
			return SOAP_NO_DATA;
		}
		else return SOAP_OK;
	}
	else 
	{
		soap->error = SOAP_HTTP_ERROR;
		DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
			"winhttp %p: resend, error %d (%s)\n", 
			soap, soap->error, winhttp_error_message(soap,soap->error) ));
		return SOAP_HTTP_ERROR;
	}
}

/* gsoap documentation:
    Called for all receive operations to fill buffer s of maximum length n. 
    Should return the number of bytes read or 0 in case of an error, e.g. EOF.
    Built-in gSOAP function: frecv
 */
static size_t 
winhttp_frecv(
    struct soap *   soap, 
    char *          a_pBuffer, 
    size_t          a_uiBufferLen ) 
{ 
    HINTERNET   hHttpRequest = (HINTERNET) soap->socket;
    size_t      uiTotalBytesRead = 0;
    //BOOL        bResult;
	DWORD       dwSize, dwDownloaded;
	LPSTR       pszOutBuffer;

    soap->error = SOAP_OK;

    DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
        "winhttp %p: frecv, available buffer len = %lu\n", 
        soap, a_uiBufferLen ));

    /* 
        NOTE: we do not check here that our connection hasn't been 
        disconnected because in HTTP/1.0 connections, it will always have been
        disconnected by now. This is because the response is checked by the 
        winhttp_fsend function to ensure that we didn't need any special 
        authentication. At that time the connection would have been 
        disconnected. This is okay however as we can still read the response
        from the request handle.
     */
    do
    {
		/* read from the connection up to our maximum amount of data */
        _ASSERTE( a_uiBufferLen <= ULONG_MAX );
		
		// Check for available data.
		dwSize = 0;
		if (!WinHttpQueryDataAvailable(hHttpRequest, &dwSize))
		{
			soap->error = GetLastError();
			DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
				"winhttp %p: connect, error %d (%s) in WinHttpReceiveResponse\n", 
				soap, soap->error, winhttp_error_message(soap,soap->error) ));
			return SOAP_NO_DATA;
		}
		if (dwSize > 0)
		{
			if (uiTotalBytesRead + dwSize < a_uiBufferLen)
			{ /* more data exist than buffer size, so chunk dwSize */
				dwSize = a_uiBufferLen - uiTotalBytesRead;
			}
			// Allocate space for the buffer.
			pszOutBuffer = (char*)malloc(dwSize+1);
			if (!pszOutBuffer)
			{
				soap->error = GetLastError();
				DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
					"winhttp %p: connect, error %d (%s) in WinHttpReceiveResponse\n", 
					soap, soap->error, winhttp_error_message(soap,soap->error) ));
				return SOAP_FATAL_ERROR;
			}
			// Read the Data.
			ZeroMemory(pszOutBuffer, dwSize+1);
			dwDownloaded = 0;
			if (!WinHttpReadData( hHttpRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
			{
				free(pszOutBuffer);
				soap->error = GetLastError();
				DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
					"winhttp %p: connect, error %d (%s) in WinHttpReceiveResponse\n", 
					soap, soap->error, winhttp_error_message(soap,soap->error) ));
				return SOAP_NO_DATA;
			}
			if (0 < dwDownloaded)
			{
				memcpy(a_pBuffer + uiTotalBytesRead, pszOutBuffer, dwDownloaded);
				uiTotalBytesRead += dwDownloaded;
			}
			free(pszOutBuffer);
		}
	} while (dwSize > 0 && uiTotalBytesRead < a_uiBufferLen );

    DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
        "winhttp %p: recv, received %lu bytes\n", soap, uiTotalBytesRead ));

    return uiTotalBytesRead;
} 

/* gsoap documentation:
    Called by client proxy multiple times, to close a socket connection before
    a new socket connection is established and at the end of communications 
    when the SOAP_IO_KEEPALIVE flag is not set and soap.keep_alive = 0 
    (indicating that the other party supports keep alive). Should return 
    SOAP_OK, or a gSOAP error code. Built-in gSOAP function: tcp_disconnect
 */
static int 
winhttp_disconnect( 
    struct soap *   soap )
{
    struct winhttp_data * pData = 
        (struct winhttp_data *) soap_lookup_plugin( soap, winhttp_id );

    soap->error = SOAP_OK;

    DBGLOG(TEST, SOAP_MESSAGE(fdebug, "winhttp %p: disconnect\n", soap ));

    /* force a disconnect by setting the disconnect flag to TRUE */
    pData->bDisconnect = TRUE;
    winhttp_have_connection( soap, pData );

    return SOAP_OK;
}


/* 
    check to ensure that our connection hasn't been disconnected 
    and disconnect remaining handles if necessary.
 */
static BOOL
winhttp_have_connection(
    struct soap *           soap,
    struct winhttp_data *   a_pData )
{
    /* close the http request if we don't have a connection */
    BOOL bCloseRequest = a_pData->bDisconnect || !a_pData->hConnection;
    if ( bCloseRequest && soap->socket != SOAP_INVALID_SOCKET )
    {
        DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
            "winhttp %p: closing request\n", soap));

        WinHttpCloseHandle( (HINTERNET) soap->socket );
        soap->socket = SOAP_INVALID_SOCKET;
    }

    /* close the connection if we don't have a request */
    if ( soap->socket == SOAP_INVALID_SOCKET && a_pData->hConnection )
    {
        DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
            "winhttp %p: closing connection\n", soap));

        WinHttpCloseHandle( a_pData->hConnection );
        a_pData->hConnection = NULL;
    }
    a_pData->bDisconnect = FALSE;

    /* clean up the send details if we don't have a request */
    if ( soap->socket == SOAP_INVALID_SOCKET )
    {
        if ( a_pData->pBuffer )
        {
            free( a_pData->pBuffer );
            a_pData->pBuffer = 0;
        }
        a_pData->uiBufferLen = 0;
        a_pData->uiBufferLenMax = INVALID_BUFFER_LENGTH;
    }

    /* we now either still have both request and connection, or neither */
    return (a_pData->hConnection != NULL);
}

static DWORD
winhttp_set_timeout(
    struct soap *           soap, 
    struct winhttp_data *   a_pData,
    const char *            a_pszTimeout,
    DWORD                   a_dwOption, /* WINHTTP_OPTION_CONNECT_TIMEOUT */
    int                     a_nTimeout )
{
    UNUSED_ARG( soap );
    UNUSED_ARG( a_pszTimeout );

    if ( a_nTimeout > 0 )
    {
        DWORD dwTimeout = a_nTimeout * 1000;
        if ( !WinHttpSetOption( a_pData->hInternet, 
            a_dwOption, &dwTimeout, sizeof(DWORD) ) )
        {
            DWORD dwErrorCode = GetLastError();
            DBGLOG(TEST, SOAP_MESSAGE(fdebug, 
                "winhttp %p: failed to set %s timeout, error %d (%s)\n", 
                soap, a_pszTimeout, dwErrorCode, 
                winhttp_error_message(soap,dwErrorCode) ));
            return dwErrorCode;
        }
    }
    return 0;
}


#ifdef SOAP_DEBUG

static const char *
winhttp_error_message(
    struct soap *   soap,
    DWORD           a_dwErrorMsgId )
{
    HINSTANCE   hModule;
    DWORD       dwResult;
    DWORD       dwFormatFlags;
    struct winhttp_data * pData = 
        (struct winhttp_data *) soap_lookup_plugin( soap, winhttp_id );

    /* free any existing error message */
    winhttp_free_error_message( pData );

    dwFormatFlags = 
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_IGNORE_INSERTS |
        FORMAT_MESSAGE_FROM_SYSTEM;

    /* load winhttp.dll for the error messages */
    hModule = LoadLibraryExA( "winhttp.dll", NULL,
        LOAD_LIBRARY_AS_DATAFILE | DONT_RESOLVE_DLL_REFERENCES );
    if ( hModule )
    {
        dwFormatFlags |= FORMAT_MESSAGE_FROM_HMODULE;
    }

    /* format the messages */
    dwResult = FormatMessageA( 
        dwFormatFlags, 
        hModule, 
        a_dwErrorMsgId, 
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR) &pData->pszErrorMessage,
        0,
        NULL );

    /* free the library if we loaded it */
    if ( hModule )
    {
        FreeLibrary( hModule );
    }

    /* remove the CR LF from the error message */
    if ( dwResult > 2 )
    {
        pData->pszErrorMessage[dwResult-2] = 0;
        return pData->pszErrorMessage;
    }
    else
    {
        const static char szUnknown[] = "(unknown)";
        return szUnknown;
    }
}

static void
winhttp_free_error_message(
    struct winhttp_data *   a_pData )
{
    if ( a_pData->pszErrorMessage )
    {
        LocalFree( a_pData->pszErrorMessage );
        a_pData->pszErrorMessage = 0;
    }
}

#endif /* SOAP_DEBUG */

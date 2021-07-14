use std::env;
use std::io::Read;

use reqwest;
use reqwest::header::CONTENT_TYPE;

use crate::error::{AgencyClientErrorKind, AgencyClientError, AgencyClientResult};
use crate::mocking::{AgencyMock, AgencyMockDecrypted, HttpClientMockResponse};
use crate::mocking;

pub async fn post_message(body_content: &Vec<u8>, url: &str) -> AgencyClientResult<Vec<u8>> {
    // todo: this function should be general, not knowing that agency exists -> move agency mocks to agency module
    if mocking::agency_mocks_enabled() {
        if HttpClientMockResponse::has_response() {
            warn!("HttpClient has mocked response");
            return HttpClientMockResponse::get_response();
        }
        if AgencyMockDecrypted::has_decrypted_mock_responses() {
            warn!("Agency requests returns empty response, decrypted mock response is available");
            return Ok(vec!());
        }
        let mocked_response = AgencyMock::get_response();
        debug!("Agency returns mocked response of length {}", mocked_response.len());
        return Ok(mocked_response);
    }

    //Setting SSL Certs location. This is needed on android platform. Or openssl will fail to verify the certs
    if cfg!(target_os = "android") {
        info!("::Android code");
        set_ssl_cert_location();
    }

    let client = reqwest::ClientBuilder::new().timeout(crate::utils::timeout::TimeoutUtils::long_timeout()).build().map_err(|err| {
        error!("error: {}", err);
        AgencyClientError::from_msg(AgencyClientErrorKind::PostMessageFailed, format!("Building reqwest client failed: {:?}", err))
    })?;
    debug!("Posting encrypted bundle to: \"{}\"", url);

    let response =
        client.post(url)
            .body(body_content.to_owned())
            .header(CONTENT_TYPE, "application/ssi-agent-wire")
            .send()
            .await
            .map_err(|err| {
                error!("error: {}", err);
                AgencyClientError::from_msg(AgencyClientErrorKind::PostMessageFailed, format!("Could not connect {:?}", err))
            })?;
    trace!("Response Header: {:?}", response);

    if !response.status().is_success() {
        let content = response.text().await.or(Err(AgencyClientError::from_msg(AgencyClientErrorKind::PostMessageFailed, "could not read response")))?.clone();
        return Err(AgencyClientError::from_msg(AgencyClientErrorKind::PostMessageFailed, format!("POST failed with: {}", content)));
    }

    Ok(response.bytes().await.or(Err(AgencyClientError::from_msg(AgencyClientErrorKind::IOError, "Failed to convert response to bytes")))?.as_ref().to_vec())
}

fn set_ssl_cert_location() {
    let ssl_cert_file = "SSL_CERT_FILE";
    env::set_var(ssl_cert_file, env::var("EXTERNAL_STORAGE").unwrap() + "/cacert.pem"); //TODO: CHANGE ME, HARDCODING FOR TESTING ONLY
    match env::var(ssl_cert_file) {
        Ok(val) => info!("{}:: {:?}", ssl_cert_file, val),
        Err(e) => error!("couldn't find var in env {}:: {}. This needs to be set on Android to make https calls.\n See https://github.com/seanmonstar/reqwest/issues/70 for more info",
                         ssl_cert_file, e),
    }
    info!("::SSL_CERT_FILE has been set");
}

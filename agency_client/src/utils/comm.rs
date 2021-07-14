use crate::{httpclient, agency_settings};
use crate::error::AgencyClientResult;

pub fn post_to_agency(body_content: &Vec<u8>) -> AgencyClientResult<Vec<u8>> {
    let endpoint = agency_settings::get_config_value(agency_settings::CONFIG_AGENCY_ENDPOINT)?;
    futures::executor::block_on(httpclient::post_message(body_content, &endpoint))
}

use api::VcxStateType;
use connection;
use error::{VcxError, VcxErrorKind, VcxResult};
use messages::{A2AMessage, A2AMessageKinds, A2AMessageV2, GeneralMessage, MessageStatusCode, parse_response_from_agency, prepare_message_for_agent, RemoteMessageType, SendRemoteMessage};
use messages::message_type::MessageTypes;
use messages::payload::{PayloadKinds, Payloads};
use messages::send_message;
use messages::thread::Thread;
use settings;
use utils::{constants, httpclient};
use utils::agent_info::get_agent_info;
use utils::httpclient::AgencyMock;
use utils::uuid::uuid;

#[derive(Debug)]
pub struct SendMessageBuilder {
    mtype: RemoteMessageType,
    to_did: String,
    to_vk: String,
    agent_did: String,
    agent_vk: String,
    payload: Vec<u8>,
    ref_msg_id: Option<String>,
    status_code: MessageStatusCode,
    uid: Option<String>,
    title: Option<String>,
    detail: Option<String>,
    version: settings::ProtocolTypes,
}

impl SendMessageBuilder {
    pub fn create() -> SendMessageBuilder {
        trace!("SendMessage::create_message >>>");

        SendMessageBuilder {
            mtype: RemoteMessageType::Other(String::new()),
            to_did: String::new(),
            to_vk: String::new(),
            agent_did: String::new(),
            agent_vk: String::new(),
            payload: Vec::new(),
            ref_msg_id: None,
            status_code: MessageStatusCode::Created,
            uid: None,
            title: None,
            detail: None,
            version: settings::get_protocol_type(),
        }
    }

    pub fn msg_type(&mut self, msg: &RemoteMessageType) -> VcxResult<&mut Self> {
        debug!("setting msg type");
        //Todo: validate msg??
        self.mtype = msg.clone();
        Ok(self)
    }

    pub fn uid(&mut self, uid: Option<&str>) -> VcxResult<&mut Self> {
        //Todo: validate msg_uid??
        self.uid = uid.map(String::from);
        Ok(self)
    }

    pub fn status_code(&mut self, code: &MessageStatusCode) -> VcxResult<&mut Self> {
        //Todo: validate that it can be parsed to number??
        self.status_code = code.clone();
        Ok(self)
    }

    pub fn edge_agent_payload(&mut self, my_vk: &str, their_vk: &str, data: &str, payload_type: PayloadKinds, thread: Option<Thread>) -> VcxResult<&mut Self> {
        //todo: is this a json value, String??
        self.payload = Payloads::encrypt(my_vk, their_vk, data, payload_type, thread)?;
        Ok(self)
    }


    pub fn ref_msg_id(&mut self, id: Option<String>) -> VcxResult<&mut Self> {
        self.ref_msg_id = id;
        Ok(self)
    }

    pub fn set_title(&mut self, title: &str) -> VcxResult<&mut Self> {
        self.title = Some(title.to_string());
        Ok(self)
    }

    pub fn set_detail(&mut self, detail: &str) -> VcxResult<&mut Self> {
        self.detail = Some(detail.to_string());
        Ok(self)
    }

    pub fn version(&mut self, version: Option<settings::ProtocolTypes>) -> VcxResult<&mut Self> {
        self.version = match version {
            Some(version) => version,
            None => settings::get_protocol_type()
        };
        Ok(self)
    }

    pub fn send_secure(&mut self) -> VcxResult<SendResponse> {
        trace!("SendMessage::send >>>");

        AgencyMock::set_next_response(constants::SEND_MESSAGE_RESPONSE.to_vec());

        let data = self.prepare_request()?;

        let response = httpclient::post_u8(&data)?;

        let result = self.parse_response(response)?;

        Ok(result)
    }

    fn parse_response(&self, response: Vec<u8>) -> VcxResult<SendResponse> {
        let mut response = parse_response_from_agency(&response, &self.version)?;

        let index = match self.version {
            // TODO: THINK better
            settings::ProtocolTypes::V1 => {
                if response.len() <= 1 {
                    return Err(VcxError::from(VcxErrorKind::InvalidHttpResponse));
                }
                1
            }
            settings::ProtocolTypes::V2 |
            settings::ProtocolTypes::V3 |
            settings::ProtocolTypes::V4 => 0
        };

        match response.remove(index) {
            A2AMessage::Version2(A2AMessageV2::SendRemoteMessageResponse(res)) =>
                Ok(SendResponse { uid: Some(res.id.clone()), uids: if res.sent { vec![res.id] } else { vec![] } }),
            _ => Err(VcxError::from(VcxErrorKind::InvalidHttpResponse))
        }
    }
}

//Todo: Every GeneralMessage extension, duplicates code
impl GeneralMessage for SendMessageBuilder {
    type Msg = SendMessageBuilder;

    fn set_agent_did(&mut self, did: String) { self.agent_did = did; }
    fn set_agent_vk(&mut self, vk: String) { self.agent_vk = vk; }
    fn set_to_did(&mut self, to_did: String) { self.to_did = to_did; }
    fn set_to_vk(&mut self, to_vk: String) { self.to_vk = to_vk; }

    fn prepare_request(&mut self) -> VcxResult<Vec<u8>> {
        let messages =
            match self.version {
                settings::ProtocolTypes::V1 |
                settings::ProtocolTypes::V2 |
                settings::ProtocolTypes::V3 |
                settings::ProtocolTypes::V4 => {
                    let msg: ::serde_json::Value = ::serde_json::from_slice(self.payload.as_slice())
                        .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidState, err))?;

                    let message = SendRemoteMessage {
                        msg_type: MessageTypes::build_v2(A2AMessageKinds::SendRemoteMessage),
                        id: uuid(),
                        mtype: self.mtype.clone(),
                        reply_to_msg_id: self.ref_msg_id.clone(),
                        send_msg: true,
                        msg,
                        title: self.title.clone(),
                        detail: self.detail.clone(),
                    };
                    vec![A2AMessage::Version2(A2AMessageV2::SendRemoteMessage(message))]
                }
            };

        prepare_message_for_agent(messages, &self.to_vk, &self.agent_did, &self.agent_vk, &self.version)
    }
}

#[derive(Debug, PartialEq)]
pub struct SendResponse {
    uid: Option<String>,
    uids: Vec<String>,
}

impl SendResponse {
    pub fn get_msg_uid(&self) -> VcxResult<String> {
        self.uids
            .get(0)
            .map(|uid| uid.to_string())
            .ok_or(VcxError::from(VcxErrorKind::InvalidJson))
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SendMessageOptions {
    pub msg_type: String,
    pub msg_title: String,
    pub ref_msg_id: Option<String>,
}

pub fn send_generic_message(connection_handle: u32, msg: &str, msg_options: &str) -> VcxResult<String> {
    if connection::get_state(connection_handle) != VcxStateType::VcxStateAccepted as u32 {
        return Err(VcxError::from(VcxErrorKind::NotReady));
    }

    let agent_info = get_agent_info()?.pw_info(connection_handle)?;

    let msg_options: SendMessageOptions = serde_json::from_str(msg_options).map_err(|_| {
        error!("Invalid SendMessage msg_options");
        VcxError::from(VcxErrorKind::InvalidConfiguration)
    })?;

    let response =
        send_message()
            .to(&agent_info.my_pw_did()?)?
            .to_vk(&agent_info.my_pw_vk()?)?
            .msg_type(&RemoteMessageType::Other(msg_options.msg_type.clone()))?
            .edge_agent_payload(&agent_info.my_pw_vk()?,
                                &agent_info.their_pw_vk()?,
                                &msg,
                                PayloadKinds::Other(msg_options.msg_type.clone()),
                                None,
            )?
            .agent_did(&agent_info.pw_agent_did()?)?
            .agent_vk(&agent_info.pw_agent_vk()?)?
            .set_title(&msg_options.msg_title)?
            .set_detail(&msg_options.msg_title)?
            .ref_msg_id(msg_options.ref_msg_id.clone())?
            .status_code(&MessageStatusCode::Accepted)?
            .version(agent_info.version()?.clone())?
            .send_secure()?;

    let msg_uid = response.get_msg_uid()?;
    Ok(msg_uid)
}

#[cfg(test)]
mod tests {
    use utils::devsetup::*;

    use super::*;

    #[test]
    #[cfg(feature = "general_test")]
    fn test_msgpack() {
        let _setup = SetupAriesMocks::init();

        trace!("test_msgpack :: initialized, going to build message");
        let mut message = SendMessageBuilder {
            mtype: RemoteMessageType::CredOffer,
            to_did: "8XFh8yBzrpJQmNyZzgoTqB".to_string(),
            to_vk: "EkVTa7SCJ5SntpYyX7CSb2pcBhiVGT9kWSagA8a9T69A".to_string(),
            agent_did: "8XFh8yBzrpJQmNyZzgoTqB".to_string(),
            agent_vk: "EkVTa7SCJ5SntpYyX7CSb2pcBhiVGT9kWSagA8a9T69A".to_string(),
            payload: "{\"hello\":\"world\"}".into(),
            ref_msg_id: Some("123".to_string()),
            status_code: MessageStatusCode::Created,
            uid: Some("123".to_string()),
            title: Some("this is the title".to_string()),
            detail: Some("this is the detail".to_string()),
            version: settings::get_protocol_type(),
        };

        trace!("test_msgpack :: message build, going to send it");
        /* just check that it doesn't panic */
        let _packed = message.prepare_request().unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_parse_send_message_bad_response() {
        let _setup = SetupAriesMocks::init();

        let result = SendMessageBuilder::create().parse_response(::utils::constants::UPDATE_PROFILE_RESPONSE.to_vec());
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_parse_msg_uid() {
        let _setup = SetupDefaults::init();

        let test_val = "devin";
        let response = SendResponse {
            uid: None,
            uids: vec![test_val.to_string()],
        };

        let uid = response.get_msg_uid().unwrap();
        assert_eq!(test_val, uid);

        let response = SendResponse {
            uid: None,
            uids: vec![],
        };

        let uid = response.get_msg_uid().unwrap_err();
        assert_eq!(VcxErrorKind::InvalidJson, uid.kind());
    }
}

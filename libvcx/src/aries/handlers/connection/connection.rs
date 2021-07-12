use core::fmt;
use std::collections::HashMap;
use std::fmt::Formatter;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{EnumAccess, Error, MapAccess, SeqAccess, Unexpected, Visitor};
use serde_json::Value;

use agency_client::get_message::Message;
use agency_client::MessageStatusCode;

use crate::aries::handlers::connection::cloud_agent::CloudAgentInfo;
use crate::aries::handlers::connection::invitee::state_machine::{InviteeFullState, InviteeState, SmConnectionInvitee};
use crate::aries::handlers::connection::inviter::state_machine::{InviterFullState, InviterState, SmConnectionInviter};
use crate::aries::handlers::connection::legacy_agent_info::LegacyAgentInfo;
use crate::aries::handlers::connection::pairwise_info::PairwiseInfo;
use crate::aries::messages::a2a::A2AMessage;
use crate::aries::messages::basic_message::message::BasicMessage;
use crate::aries::messages::connection::did_doc::DidDoc;
use crate::aries::messages::connection::invite::Invitation;
use crate::aries::messages::discovery::disclose::ProtocolDescriptor;
use crate::aries::utils::send_message;
use crate::error::prelude::*;
use crate::utils::serialization::SerializableObjectWithState;

#[derive(Clone)]
pub struct Connection {
    connection_sm: SmConnection,
    cloud_agent_info: CloudAgentInfo,
    autohop_enabled: bool,
}

#[derive(Clone)]
pub enum SmConnection {
    Inviter(SmConnectionInviter),
    Invitee(SmConnectionInvitee),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SmConnectionState {
    Inviter(InviterFullState),
    Invitee(InviteeFullState),
}

#[derive(Debug, Serialize)]
struct ConnectionInfo {
    my: SideConnectionInfo,
    their: Option<SideConnectionInfo>,
}

#[derive(Debug, PartialEq)]
pub enum ConnectionState {
    Inviter(InviterState),
    Invitee(InviteeState),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SideConnectionInfo {
    did: String,
    recipient_keys: Vec<String>,
    routing_keys: Vec<String>,
    service_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocols: Option<Vec<ProtocolDescriptor>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Actor {
    Inviter,
    Invitee,
}

impl Connection {
    /**
    Create Inviter connection state machine
     */
    pub fn create(source_id: &str, autohop: bool) -> VcxResult<Connection> {
        trace!("Connection::create >>> source_id: {}", source_id);
        let pairwise_info = PairwiseInfo::create()?;
        let cloud_agent_info = CloudAgentInfo::create(&pairwise_info)?;
        Ok(Connection {
            cloud_agent_info,
            connection_sm: SmConnection::Inviter(SmConnectionInviter::new(source_id, pairwise_info, send_message)),
            autohop_enabled: autohop,
        })
    }

    /**
    Create Invitee connection state machine
     */
    pub fn create_with_invite(source_id: &str, invitation: Invitation, autohop_enabled: bool) -> VcxResult<Connection> {
        trace!("Connection::create_with_invite >>> source_id: {}", source_id);
        let pairwise_info = PairwiseInfo::create()?;
        let cloud_agent_info = CloudAgentInfo::create(&pairwise_info)?;
        let mut connection = Connection {
            cloud_agent_info,
            connection_sm: SmConnection::Invitee(SmConnectionInvitee::new(source_id, pairwise_info, send_message)),
            autohop_enabled,
        };
        connection.process_invite(invitation)?;
        Ok(connection)
    }

    pub fn from_parts(source_id: String, pairwise_info: PairwiseInfo, cloud_agent_info: CloudAgentInfo, state: SmConnectionState, autohop_enabled: bool) -> Connection {
        match state {
            SmConnectionState::Inviter(state) => {
                Connection {
                    cloud_agent_info,
                    connection_sm: SmConnection::Inviter(SmConnectionInviter::from(source_id, pairwise_info, state, send_message)),
                    autohop_enabled,
                }
            }
            SmConnectionState::Invitee(state) => {
                Connection {
                    cloud_agent_info,
                    connection_sm: SmConnection::Invitee(SmConnectionInvitee::from(source_id, pairwise_info, state, send_message)),
                    autohop_enabled,
                }
            }
        }
    }

    pub fn source_id(&self) -> String {
        match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                sm_inviter.source_id()
            }
            SmConnection::Invitee(sm_invitee) => {
                sm_invitee.source_id()
            }
        }.into()
    }

    pub fn get_state(&self) -> ConnectionState {
        match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                ConnectionState::Inviter(sm_inviter.get_state())
            }
            SmConnection::Invitee(sm_invitee) => {
                ConnectionState::Invitee(sm_invitee.get_state())
            }
        }
    }

    pub fn pairwise_info(&self) -> &PairwiseInfo {
        match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                sm_inviter.pairwise_info()
            }
            SmConnection::Invitee(sm_invitee) => {
                sm_invitee.pairwise_info()
            }
        }
    }

    pub fn cloud_agent_info(&self) -> CloudAgentInfo {
        self.cloud_agent_info.clone()
    }

    // pub fn bootstrap_agent_info(&self) -> Option<&PairwiseInfo> {
    //     match &self.connection_sm {
    //         SmConnection::Inviter(sm_inviter) => {
    //             sm_inviter.prev_agent_info()
    //         }
    //         SmConnection::Invitee(_sm_invitee) => None
    //     }
    // }

    pub fn remote_did(&self) -> VcxResult<String> {
        match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                sm_inviter.remote_did()
            }
            SmConnection::Invitee(sm_invitee) => {
                sm_invitee.remote_did()
            }
        }
    }

    pub fn remote_vk(&self) -> VcxResult<String> {
        match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                sm_inviter.remote_vk()
            }
            SmConnection::Invitee(sm_invitee) => {
                sm_invitee.remote_vk()
            }
        }
    }

    pub fn state_object(&self) -> SmConnectionState {
        match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                SmConnectionState::Inviter(sm_inviter.state_object().clone())
            }
            SmConnection::Invitee(sm_invitee) => {
                SmConnectionState::Invitee(sm_invitee.state_object().clone())
            }
        }
    }

    pub fn get_source_id(&self) -> String {
        match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                sm_inviter.source_id()
            }
            SmConnection::Invitee(sm_invitee) => {
                sm_invitee.source_id()
            }
        }.to_string()
    }

    pub fn get_protocols(&self) -> Vec<ProtocolDescriptor> {
        match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                sm_inviter.get_protocols()
            }
            SmConnection::Invitee(sm_invitee) => {
                sm_invitee.get_protocols()
            }
        }
    }

    pub fn get_remote_protocols(&self) -> Option<Vec<ProtocolDescriptor>> {
        match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                sm_inviter.get_remote_protocols()
            }
            SmConnection::Invitee(sm_invitee) => {
                sm_invitee.get_remote_protocols()
            }
        }
    }

    pub fn is_in_null_state(&self) -> bool {
        match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                sm_inviter.is_in_null_state()
            }
            SmConnection::Invitee(sm_invitee) => {
                sm_invitee.is_in_null_state()
            }
        }
    }

    pub fn their_did_doc(&self) -> Option<DidDoc> {
        match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                sm_inviter.their_did_doc()
            }
            SmConnection::Invitee(sm_invitee) => {
                sm_invitee.their_did_doc()
            }
        }
    }

    /**
    Invitee operation
     */
    pub fn process_invite(&mut self, invitation: Invitation) -> VcxResult<()> {
        trace!("Connection::process_invite >>> invitation: {:?}", invitation);
        self.connection_sm = match &self.connection_sm {
            SmConnection::Inviter(_sm_inviter) => {
                return Err(VcxError::from_msg(VcxErrorKind::NotReady, "Invalid action"));
            }
            SmConnection::Invitee(sm_invitee) => {
                SmConnection::Invitee(sm_invitee.clone().handle_invitation(invitation)?)
            }
        };
        Ok(())
    }

    /**
    If called on Inviter in Invited state returns invitation to connect with him. Returns error in other states.
    If called on Invitee, returns error
     */
    pub fn get_invite_details(&self) -> Option<&Invitation> {
        trace!("Connection::get_invite_details >>>");
        match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                sm_inviter.get_invitation().clone()
            }
            SmConnection::Invitee(_sm_invitee) => {
                None
            }
        }
    }

    pub fn find_message_to_handle(&self, messages: HashMap<String, A2AMessage>) -> Option<(String, A2AMessage)> {
        match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                sm_inviter.find_message_to_handle(messages)
            }
            SmConnection::Invitee(sm_invitee) => {
                sm_invitee.find_message_to_handle(messages)
            }
        }
    }

    pub fn needs_message(&self) -> bool {
        match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                sm_inviter.needs_message()
            }
            SmConnection::Invitee(sm_invitee) => {
                sm_invitee.needs_message()
            }
        }
    }

    // fn _get_bootstrap_agent_messages(&self, remote_vk: VcxResult<String>, bootstrap_agent_info: Option<&PairwiseInfo>) -> VcxResult<Option<(HashMap<String, A2AMessage>, PairwiseInfo)>> {
    //     let expected_sender_vk = match remote_vk {
    //         Ok(vk) => vk,
    //         Err(_) => return Ok(None)
    //     };
    //     if let Some(bootstrap_agent_info) = bootstrap_agent_info {
    //         trace!("Connection::_get_bootstrap_agent_messages >>> Inviter found no message to handle on main connection agent. Will check bootstrap agent.");
    //         let messages = bootstrap_agent_info.get_messages(&expected_sender_vk)?;
    //         return Ok(Some((messages, bootstrap_agent_info.clone())));
    //     }
    //     Ok(None)
    // }

    fn _update_state(&mut self, message: Option<A2AMessage>) -> VcxResult<()> {
        let (new_connection_sm, can_autohop) = match &self.connection_sm {
            SmConnection::Inviter(_) => {
                self._step_inviter(message)?
            }
            SmConnection::Invitee(_) => {
                self._step_invitee(message)?
            }
        };
        *self = new_connection_sm;
        if can_autohop && self.autohop_enabled.clone() {
            self._update_state(None)
        } else {
            Ok(())
        }
    }

    pub fn update_state(&mut self) -> VcxResult<()> {
        if self.is_in_null_state() {
            warn!("Connection::update_state :: update state on connection in null state is ignored");
            return Ok(());
        }

        let messages = self.get_messages_noauth()?;
        trace!("Connection::update_state >>> retrieved messages {:?}", messages);

        match self.find_message_to_handle(messages) {
            Some((uid, message)) => {
                trace!("Connection::update_state >>> handling message uid: {:?}", uid);
                self._update_state(Some(message))?;
                self.cloud_agent_info().clone().update_message_status(self.pairwise_info(), uid)?;
            }
            None => {
                // Todo: Restore lookup into bootstrap cloud agent
                // self.bootstrap_agent_info()
                // if let Some((messages, bootstrap_agent_info)) = self._get_bootstrap_agent_messages(self.remote_vk(), )? {
                //     if let Some((uid, message)) = self.find_message_to_handle(messages) {
                //         trace!("Connection::update_state >>> handling message found on bootstrap agent uid: {:?}", uid);
                //         self._update_state(Some(message))?;
                //         bootstrap_agent_info.update_message_status(uid)?;
                //     }
                // } else {
                trace!("Connection::update_state >>> trying to update state without message");
                self._update_state(None)?;
                // }
            }
        }
        Ok(())
    }

    /**
    Perform state machine transition using supplied message.
     */
    pub fn update_state_with_message(&mut self, message: &A2AMessage) -> VcxResult<()> {
        trace!("Connection: update_state_with_message: {:?}", message);
        if self.is_in_null_state() {
            warn!("Connection::update_state_with_message :: update state on connection in null state is ignored");
            return Ok(());
        }
        self._update_state(Some(message.clone()))?;
        Ok(())
    }

    fn _step_inviter(&self, message: Option<A2AMessage>) -> VcxResult<(Connection, bool)> {
        match self.connection_sm.clone() {
            SmConnection::Inviter(sm_inviter) => {
                let (sm_inviter, new_cloud_agent_info, can_autohop) = match message {
                    Some(message) => match message {
                        A2AMessage::ConnectionRequest(request) => {
                            let new_pairwise_info = PairwiseInfo::create()?;
                            let new_cloud_agent = CloudAgentInfo::create(&new_pairwise_info)?;
                            let new_routing_keys = new_cloud_agent.routing_keys()?;
                            let new_service_endpoint = new_cloud_agent.service_endpoint()?;
                            let sm_connection = sm_inviter.handle_connection_request(request, &new_pairwise_info, new_routing_keys, new_service_endpoint)?;
                            (sm_connection, Some(new_cloud_agent), true)
                        }
                        A2AMessage::Ack(ack) => {
                            (sm_inviter.handle_ack(ack)?, None, false)
                        }
                        A2AMessage::Ping(ping) => {
                            (sm_inviter.handle_ping(ping)?, None, false)
                        }
                        A2AMessage::ConnectionProblemReport(problem_report) => {
                            (sm_inviter.handle_problem_report(problem_report)?, None, false)
                        }
                        A2AMessage::PingResponse(ping_response) => {
                            (sm_inviter.handle_ping_response(ping_response)?, None, false)
                        }
                        A2AMessage::Query(query) => {
                            (sm_inviter.handle_discovery_query(query)?, None, false)
                        }
                        A2AMessage::Disclose(disclose) => {
                            (sm_inviter.handle_disclose(disclose)?, None, false)
                        }
                        _ => {
                            (sm_inviter.clone(), None, false)
                        }
                    }
                    None => {
                        if let InviterFullState::Requested(_) = sm_inviter.state_object() {
                            (sm_inviter.handle_send_response()?, None, false)
                        } else {
                            (sm_inviter.clone(), None, false)
                        }
                    }
                };

                let connection = Connection {
                    cloud_agent_info: new_cloud_agent_info.unwrap_or(self.cloud_agent_info.clone()),
                    connection_sm: SmConnection::Inviter(sm_inviter),
                    autohop_enabled: self.autohop_enabled.clone(),
                };

                Ok((connection, can_autohop))
            }
            SmConnection::Invitee(_) => {
                Err(VcxError::from_msg(VcxErrorKind::NotReady, "Invalid operation, called \
                _step_inviter on Invitee connection."))
            }
        }
    }


    fn _step_invitee(&self, message: Option<A2AMessage>) -> VcxResult<(Connection, bool)> {
        match self.connection_sm.clone() {
            SmConnection::Invitee(sm_invitee) => {
                let (sm_invitee, can_autohop) = match message {
                    Some(message) => match message {
                        A2AMessage::ConnectionInvitation(invitation) => {
                            (sm_invitee.handle_invitation(invitation)?, false)
                        }
                        A2AMessage::ConnectionResponse(response) => {
                            (sm_invitee.handle_connection_response(response)?, true)
                        }
                        A2AMessage::Ack(ack) => {
                            (sm_invitee.handle_ack(ack)?, false)
                        }
                        A2AMessage::Ping(ping) => {
                            (sm_invitee.handle_ping(ping)?, false)
                        }
                        A2AMessage::ConnectionProblemReport(problem_report) => {
                            (sm_invitee.handle_problem_report(problem_report)?, false)
                        }
                        A2AMessage::PingResponse(ping_response) => {
                            (sm_invitee.handle_ping_response(ping_response)?, false)
                        }
                        A2AMessage::Query(query) => {
                            (sm_invitee.handle_discovery_query(query)?, false)
                        }
                        A2AMessage::Disclose(disclose) => {
                            (sm_invitee.handle_disclose(disclose)?, false)
                        }
                        _ => {
                            (sm_invitee.clone(), false)
                        }
                    }
                    None => {
                        (sm_invitee.handle_send_ack()?, false)
                    }
                };
                let connection = Connection {
                    connection_sm: SmConnection::Invitee(sm_invitee),
                    cloud_agent_info: self.cloud_agent_info.clone(),
                    autohop_enabled: self.autohop_enabled.clone(),
                };
                Ok((connection, can_autohop))
            }
            SmConnection::Inviter(_) => {
                Err(VcxError::from_msg(VcxErrorKind::NotReady, "Invalid operation, called \
                _step_invitee on Inviter connection."))
            }
        }
    }

    /**
    If called on Inviter, creates initial connection agent and generates invitation
    If called on Invitee, creates connection agent and send connection request using info from connection invitation
     */
    pub fn connect(&mut self) -> VcxResult<()> {
        trace!("Connection::connect >>> source_id: {}", self.source_id());
        self.connection_sm = match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                SmConnection::Inviter(sm_inviter.clone().handle_connect(self.cloud_agent_info.routing_keys()?, self.cloud_agent_info.service_endpoint()?)?)
            }
            SmConnection::Invitee(sm_invitee) => {
                SmConnection::Invitee(sm_invitee.clone().handle_connect(self.cloud_agent_info.routing_keys()?, self.cloud_agent_info.service_endpoint()?)?)
            }
        };
        Ok(())
    }

    /**
    Updates status of a message (received from connection counterparty) in agency.
     */
    pub fn update_message_status(&self, uid: String) -> VcxResult<()> {
        trace!("Connection::update_message_status >>> uid: {:?}", uid);
        self.cloud_agent_info().update_message_status(self.pairwise_info(), uid)
    }

    /**
Get messages received from connection counterparty.
 */
    pub fn get_messages_noauth(&self) -> VcxResult<HashMap<String, A2AMessage>> {
        match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                let messages = self.cloud_agent_info().get_messages_noauth(sm_inviter.pairwise_info())?;
                Ok(messages)
            }
            SmConnection::Invitee(sm_invitee) => {
                let messages = self.cloud_agent_info().get_messages_noauth(sm_invitee.pairwise_info())?;
                Ok(messages)
            }
        }
    }

    /**
    Get messages received from connection counterparty.
     */
    pub fn get_messages(&self) -> VcxResult<HashMap<String, A2AMessage>> {
        let expected_sender_vk = self.get_expected_sender_vk()?;
        match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                let messages = self.cloud_agent_info().get_messages(&expected_sender_vk, sm_inviter.pairwise_info())?;
                Ok(messages)
            }
            SmConnection::Invitee(sm_invitee) => {
                let messages = self.cloud_agent_info().get_messages(&expected_sender_vk, sm_invitee.pairwise_info())?;
                Ok(messages)
            }
        }
    }

    fn get_expected_sender_vk(&self) -> VcxResult<String> {
        self.remote_vk()
            .map_err(|_err|
                VcxError::from_msg(VcxErrorKind::NotReady, "Verkey of connection counterparty \
                is not known, hence it would be impossible to authenticate message downloaded by id.")
            )
    }

    /**
    Get messages received from connection counterparty by id.
     */
    pub fn get_message_by_id(&self, msg_id: &str) -> VcxResult<A2AMessage> {
        trace!("Connection: get_message_by_id >>> msg_id: {}", msg_id);
        let expected_sender_vk = self.get_expected_sender_vk()?;
        self.cloud_agent_info().get_message_by_id(msg_id, &expected_sender_vk, self.pairwise_info())
    }

    pub fn send_message_closure(&self) -> VcxResult<impl Fn(&A2AMessage) -> VcxResult<()>> {
        trace!("send_message_closure >>>");
        let did_doc = self.their_did_doc()
            .ok_or(VcxError::from_msg(VcxErrorKind::NotReady, "Cannot send message: Remote Connection information is not set"))?;
        let sender_vk = self.pairwise_info().pw_vk.clone();
        return Ok(move |a2a_message: &A2AMessage| {
            send_message(&sender_vk, &did_doc, a2a_message)
        });
    }

    fn parse_generic_message(message: &str) -> A2AMessage {
        match ::serde_json::from_str::<A2AMessage>(message) {
            Ok(a2a_message) => a2a_message,
            Err(_) => {
                BasicMessage::create()
                    .set_content(message.to_string())
                    .set_time()
                    .to_a2a_message()
            }
        }
    }

    pub fn send_generic_message(&self, message: &str) -> VcxResult<String> {
        trace!("Connection::send_generic_message >>> message: {:?}", message);

        let message = Connection::parse_generic_message(message);
        let send_message = self.send_message_closure()?;
        send_message(&message).map(|_| String::new())
    }

    pub fn send_ping(&mut self, comment: Option<String>) -> VcxResult<()> {
        trace!("Connection::send_ping >>> comment: {:?}", comment);
        self.connection_sm = match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                SmConnection::Inviter(sm_inviter.clone().handle_send_ping(comment)?)
            }
            SmConnection::Invitee(sm_invitee) => {
                SmConnection::Invitee(sm_invitee.clone().handle_send_ping(comment)?)
            }
        };
        Ok(())
    }

    pub fn delete(&self) -> VcxResult<()> {
        trace!("Connection: delete >>> {:?}", self.source_id());
        self.cloud_agent_info().destroy(self.pairwise_info())
    }

    pub fn send_discovery_features(&mut self, query: Option<String>, comment: Option<String>) -> VcxResult<()> {
        trace!("Connection::send_discovery_features_query >>> query: {:?}, comment: {:?}", query, comment);
        self.connection_sm = match &self.connection_sm {
            SmConnection::Inviter(sm_inviter) => {
                SmConnection::Inviter(sm_inviter.clone().handle_discover_features(query, comment)?)
            }
            SmConnection::Invitee(sm_invitee) => {
                SmConnection::Invitee(sm_invitee.clone().handle_discover_features(query, comment)?)
            }
        };
        Ok(())
    }

    pub fn get_connection_info(&self) -> VcxResult<String> {
        trace!("Connection::get_connection_info >>>");

        let agent_info = self.cloud_agent_info().clone();
        let pairwise_info = self.pairwise_info();
        let recipient_keys = vec!(pairwise_info.pw_vk.clone());

        let current = SideConnectionInfo {
            did: pairwise_info.pw_did.clone(),
            recipient_keys: recipient_keys.clone(),
            routing_keys: agent_info.routing_keys()?,
            service_endpoint: agent_info.service_endpoint()?,
            protocols: Some(self.get_protocols()),
        };

        let remote = match self.their_did_doc() {
            Some(did_doc) =>
                Some(SideConnectionInfo {
                    did: did_doc.id.clone(),
                    recipient_keys: did_doc.recipient_keys(),
                    routing_keys: did_doc.routing_keys(),
                    service_endpoint: did_doc.get_endpoint(),
                    protocols: self.get_remote_protocols(),
                }),
            None => None
        };

        let connection_info = ConnectionInfo { my: current, their: remote };

        let connection_info_json = serde_json::to_string(&connection_info)
            .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidState, format!("Cannot serialize ConnectionInfo: {:?}", err)))?;

        return Ok(connection_info_json);
    }

    pub fn download_messages(&self, status_codes: Option<Vec<MessageStatusCode>>, uids: Option<Vec<String>>) -> VcxResult<Vec<Message>> {
        let expected_sender_vk = self.remote_vk()?;
        let msgs = self.cloud_agent_info()
            .download_encrypted_messages(uids, status_codes, self.pairwise_info())?
            .iter()
            .map(|msg| msg.decrypt_auth(&expected_sender_vk).map_err(|err| err.into()))
            .collect::<VcxResult<Vec<Message>>>()?;
        Ok(msgs)
    }

    pub fn to_string(&self) -> VcxResult<String> {
        serde_json::to_string(&self)
            .map_err(|err| VcxError::from_msg(VcxErrorKind::SerializationError, format!("Cannot serialize Connection: {:?}", err)))
    }

    pub fn from_string(connection_data: &str) -> VcxResult<Connection> {
        serde_json::from_str(connection_data)
            .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot deserialize Connection: {:?}", err)))
    }
}

impl Serialize for Connection
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let (state, pairwise_info, cloud_agent_info, source_id) = self.to_owned().into();
        let data = LegacyAgentInfo {
            pw_did: pairwise_info.pw_did,
            pw_vk: pairwise_info.pw_vk,
            agent_did: cloud_agent_info.agent_did,
            agent_vk: cloud_agent_info.agent_vk,
        };
        let object = SerializableObjectWithState::V1 { data, state, source_id };
        serializer.serialize_some(&object)
    }
}

struct ConnectionVisitor;

impl<'de> Visitor<'de> for ConnectionVisitor {
    type Value = Connection;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("serialized Connection object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, <A as MapAccess<'de>>::Error> where
        A: MapAccess<'de>, {
        let mut map_value = serde_json::Map::new();
        while let Some(key) = map.next_key()? {
            let k: String = key;
            let v: Value = map.next_value()?;
            map_value.insert(k, v);
        }
        let obj = Value::from(map_value);
        let ver: SerializableObjectWithState<LegacyAgentInfo, SmConnectionState> = serde_json::from_value(obj)
            .map_err(|err| A::Error::custom(err.to_string()))?;
        match ver {
            SerializableObjectWithState::V1 { data, state, source_id } => {
                let pairwise_info = PairwiseInfo { pw_did: data.pw_did, pw_vk: data.pw_vk };
                let cloud_agent_info = CloudAgentInfo { agent_did: data.agent_did, agent_vk: data.agent_vk };
                Ok((state, pairwise_info, cloud_agent_info, source_id).into())
            }
        }
    }
}

impl<'de> Deserialize<'de> for Connection {
    fn deserialize<D>(deserializer: D) -> Result<Connection, D::Error>
        where
            D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ConnectionVisitor)
    }
}

impl Into<(SmConnectionState, PairwiseInfo, CloudAgentInfo, String)> for Connection {
    fn into(self) -> (SmConnectionState, PairwiseInfo, CloudAgentInfo, String) {
        (self.state_object(), self.pairwise_info().to_owned(), self.cloud_agent_info().to_owned(), self.source_id())
    }
}

impl From<(SmConnectionState, PairwiseInfo, CloudAgentInfo, String)> for Connection {
    fn from((state, pairwise_info, cloud_agent_info, source_id): (SmConnectionState, PairwiseInfo, CloudAgentInfo, String)) -> Connection {
        Connection::from_parts(source_id, pairwise_info, cloud_agent_info, state, true)
    }
}


#[cfg(test)]
pub mod tests {
    use std::thread;
    use std::time::Duration;

    use serde_json::Value;

    use agency_client::get_message::download_messages_noauth;
    use agency_client::MessageStatusCode;
    use agency_client::mocking::AgencyMockDecrypted;
    use agency_client::update_message::{UIDsByConn, update_agency_messages};

    use crate::{aries, settings, utils};
    use crate::aries::messages::ack::tests::_ack;
    use crate::utils::constants;
    use crate::utils::devsetup::*;
    use crate::utils::devsetup_agent::test::{Alice, Faber, TestAgent};
    use crate::utils::mockdata::mockdata_connection::{ARIES_CONNECTION_ACK, ARIES_CONNECTION_INVITATION, ARIES_CONNECTION_REQUEST, CONNECTION_SM_INVITEE_COMPLETED, CONNECTION_SM_INVITEE_INVITED, CONNECTION_SM_INVITEE_REQUESTED, CONNECTION_SM_INVITER_COMPLETED};

    use super::*;

    #[test]
    #[cfg(feature = "general_test")]
    fn test_deserialize_connection_inviter_completed() {
        let _setup = SetupMocks::init();

        let connection = Connection::from_string(CONNECTION_SM_INVITER_COMPLETED).unwrap();
        let _second_string = connection.to_string();

        assert_eq!(connection.pairwise_info().pw_did, "2ZHFFhzA2XtTD6hJqzL7ux");
        assert_eq!(connection.pairwise_info().pw_vk, "rCw3x5h1jS6gPo7rRrt3EYbXXe5nNjnGbdf1jAwUxuj");
        assert_eq!(connection.cloud_agent_info().agent_did, "EZrZyu4bfydm4ByNm56kPP");
        assert_eq!(connection.cloud_agent_info().agent_vk, "8Ps2WosJ9AV1eXPoJKsEJdM3NchPhSyS8qFt6LQUTKv2");
        assert_eq!(connection.get_state(), ConnectionState::Inviter(InviterState::Completed));
    }

    fn test_deserialize_and_serialize(sm_serialized: &str) {
        let original_object: Value = serde_json::from_str(sm_serialized).unwrap();
        let connection = Connection::from_string(sm_serialized).unwrap();
        let reserialized = connection.to_string().unwrap();
        let reserialized_object: Value = serde_json::from_str(&reserialized).unwrap();

        assert_eq!(original_object, reserialized_object);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_deserialize_and_serialize_should_produce_the_same_object() {
        let _setup = SetupMocks::init();

        test_deserialize_and_serialize(CONNECTION_SM_INVITEE_INVITED);
        test_deserialize_and_serialize(CONNECTION_SM_INVITEE_REQUESTED);
        test_deserialize_and_serialize(CONNECTION_SM_INVITEE_COMPLETED);
        test_deserialize_and_serialize(CONNECTION_SM_INVITER_COMPLETED);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_serialize_deserialize() {
        let _setup = SetupMocks::init();

        let connection = Connection::create("test_serialize_deserialize", true).unwrap();
        let first_string = connection.to_string().unwrap();

        let connection2 = Connection::from_string(&first_string).unwrap();
        let second_string = connection2.to_string().unwrap();

        assert_eq!(first_string, second_string);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_serialize_deserialize_serde() {
        let _setup = SetupMocks::init();

        let connection = Connection::create("test_serialize_deserialize", true).unwrap();
        let first_string = serde_json::to_string(&connection).unwrap();

        let connection: Connection = serde_json::from_str(&first_string).unwrap();
        let second_string = serde_json::to_string(&connection).unwrap();
        assert_eq!(first_string, second_string);
    }


    pub fn create_connected_connections(consumer: &mut Alice, institution: &mut Faber) -> (Connection, Connection) {
        debug!("Institution is going to create connection.");
        institution.activate().unwrap();
        let mut institution_to_consumer = Connection::create("consumer", true).unwrap();
        let _my_public_did = settings::get_config_value(settings::CONFIG_INSTITUTION_DID).unwrap();
        institution_to_consumer.connect().unwrap();
        let details = institution_to_consumer.get_invite_details().unwrap();

        consumer.activate().unwrap();
        debug!("Consumer is going to accept connection invitation.");
        let mut consumer_to_institution = Connection::create_with_invite("institution", details.clone(), true).unwrap();

        consumer_to_institution.connect().unwrap();
        consumer_to_institution.update_state().unwrap();

        debug!("Institution is going to process connection request.");
        institution.activate().unwrap();
        thread::sleep(Duration::from_millis(500));
        institution_to_consumer.update_state().unwrap();
        assert_eq!(ConnectionState::Inviter(InviterState::Responded), institution_to_consumer.get_state());

        debug!("Consumer is going to complete the connection protocol.");
        consumer.activate().unwrap();
        consumer_to_institution.update_state().unwrap();
        assert_eq!(ConnectionState::Invitee(InviteeState::Completed), consumer_to_institution.get_state());

        debug!("Institution is going to complete the connection protocol.");
        institution.activate().unwrap();
        thread::sleep(Duration::from_millis(500));
        institution_to_consumer.update_state().unwrap();
        assert_eq!(ConnectionState::Inviter(InviterState::Completed), institution_to_consumer.get_state());

        (consumer_to_institution, institution_to_consumer)
    }

    #[cfg(feature = "agency_pool_tests")]
    #[test]
    fn test_send_and_download_messages() {
        let _setup = SetupLibraryAgencyV2::init();
        let mut institution = Faber::setup();
        let mut consumer = Alice::setup();

        let (alice_to_faber, faber_to_alice) = create_connected_connections(&mut consumer, &mut institution);

        institution.activate().unwrap();
        faber_to_alice.send_generic_message("Hello Alice").unwrap();
        faber_to_alice.send_generic_message("How are you Alice?").unwrap();

        consumer.activate().unwrap();
        alice_to_faber.send_generic_message("Hello Faber").unwrap();

        thread::sleep(Duration::from_millis(1000));

        let all_messages = download_messages_noauth(None, None, None).unwrap();
        assert_eq!(all_messages.len(), 2);
        assert_eq!(all_messages[1].msgs.len(), 3);
        assert!(all_messages[1].msgs[0].decrypted_msg.is_some());
        assert!(all_messages[1].msgs[1].decrypted_msg.is_some());

        let received = download_messages_noauth(None, Some(vec![MessageStatusCode::Received.to_string()]), None).unwrap();
        assert_eq!(received.len(), 2);
        assert_eq!(received[1].msgs.len(), 2);
        assert!(received[1].msgs[0].decrypted_msg.is_some());
        assert_eq!(received[1].msgs[0].status_code, MessageStatusCode::Received);
        assert!(received[1].msgs[1].decrypted_msg.is_some());

        // there should be messages in "Reviewed" status connections/1.0/response from Aries-Faber connection protocol
        let reviewed = download_messages_noauth(None, Some(vec![MessageStatusCode::Reviewed.to_string()]), None).unwrap();
        assert_eq!(reviewed.len(), 2);
        assert_eq!(reviewed[1].msgs.len(), 1);
        assert!(reviewed[1].msgs[0].decrypted_msg.is_some());
        assert_eq!(reviewed[1].msgs[0].status_code, MessageStatusCode::Reviewed);

        let rejected = download_messages_noauth(None, Some(vec![MessageStatusCode::Rejected.to_string()]), None).unwrap();
        assert_eq!(rejected.len(), 2);
        assert_eq!(rejected[1].msgs.len(), 0);

        let specific = download_messages_noauth(None, None, Some(vec![received[1].msgs[0].uid.clone()])).unwrap();
        assert_eq!(specific.len(), 2);
        assert_eq!(specific[1].msgs.len(), 1);
        let msg = specific[1].msgs[0].decrypted_msg.clone().unwrap();
        let msg_aries_value: Value = serde_json::from_str(&msg).unwrap();
        assert!(msg_aries_value.is_object());
        assert!(msg_aries_value["@id"].is_string());
        assert!(msg_aries_value["@type"].is_string());
        assert!(msg_aries_value["content"].is_string());

        let unknown_did = "CmrXdgpTXsZqLQtGpX5Yee".to_string();
        let empty = download_messages_noauth(Some(vec![unknown_did]), None, None).unwrap();
        assert_eq!(empty.len(), 0);
    }

    #[test]
    #[cfg(feature = "agency_v2")]
    fn test_connection_send_works() {
        let _setup = SetupEmpty::init();
        let mut faber = Faber::setup();
        let mut alice = Alice::setup();

        let invite = faber.create_invite();
        alice.accept_invite(&invite);

        faber.update_state(3);
        alice.update_state(4);
        faber.update_state(4);

        let uid: String;
        let message = _ack();

        info!("test_connection_send_works:: Test if Send Message works");
        {
            faber.activate().unwrap();
            faber.connection.send_message_closure().unwrap()(&message.to_a2a_message()).unwrap();
        }

        {
            info!("test_connection_send_works:: Test if Get Messages works");
            alice.activate().unwrap();

            let messages = alice.connection.get_messages().unwrap();
            assert_eq!(1, messages.len());

            uid = messages.keys().next().unwrap().clone();
            let received_message = messages.values().next().unwrap().clone();

            match received_message {
                A2AMessage::Ack(received_message) => assert_eq!(message, received_message.clone()),
                _ => assert!(false)
            }
        }

        info!("test_connection_send_works:: Test if Get Message by id works");
        {
            alice.activate().unwrap();

            let message = alice.connection.get_message_by_id(&uid.clone()).unwrap();

            match message {
                A2AMessage::Ack(ack) => assert_eq!(_ack(), ack),
                _ => assert!(false)
            }
        }

        info!("test_connection_send_works:: Test if Update Message Status works");
        {
            alice.activate().unwrap();

            alice.connection.update_message_status(uid).unwrap();
            let messages = alice.connection.get_messages().unwrap();
            assert_eq!(0, messages.len());
        }

        info!("test_connection_send_works:: Test if Send Basic Message works");
        {
            faber.activate().unwrap();

            let basic_message = r#"Hi there"#;
            faber.connection.send_generic_message(basic_message).unwrap();

            alice.activate().unwrap();

            let messages = alice.connection.get_messages().unwrap();
            assert_eq!(1, messages.len());

            let uid = messages.keys().next().unwrap().clone();
            let message = messages.values().next().unwrap().clone();

            match message {
                A2AMessage::BasicMessage(message) => assert_eq!(basic_message, message.content),
                _ => assert!(false)
            }
            alice.connection.update_message_status(uid).unwrap();
        }

        info!("test_connection_send_works:: Test if Download Messages");
        {
            use agency_client::get_message::{MessageByConnection, Message};

            let credential_offer = aries::messages::issuance::credential_offer::tests::_credential_offer();

            faber.activate().unwrap();
            faber.connection.send_message_closure().unwrap()(&credential_offer.to_a2a_message()).unwrap();

            alice.activate().unwrap();

            let msgs = alice.connection.download_messages(Some(vec![MessageStatusCode::Received]), None).unwrap();
            let message: Message = msgs[0].clone();
            let decrypted_msg = message.decrypted_msg.unwrap();
            let _payload: aries::messages::issuance::credential_offer::CredentialOffer = serde_json::from_str(&decrypted_msg).unwrap();

            alice.connection.update_message_status(message.uid.clone()).unwrap()
        }
    }

    #[cfg(feature = "agency_v2")]
    #[test]
    fn test_download_messages() {
        let _setup = SetupEmpty::init();
        let mut institution = Faber::setup();
        let mut consumer1 = Alice::setup();
        let mut consumer2 = Alice::setup();
        let (consumer1_to_institution, institution_to_consumer1) = create_connected_connections(&mut consumer1, &mut institution);
        let (consumer2_to_institution, institution_to_consumer2) = create_connected_connections(&mut consumer2, &mut institution);

        let consumer1_pwdid = consumer1_to_institution.remote_did().unwrap();
        let consumer2_pwdid = consumer2_to_institution.remote_did().unwrap();

        consumer1.activate().unwrap();
        consumer1_to_institution.send_generic_message("Hello Institution from consumer1").unwrap();
        consumer2.activate().unwrap();
        consumer2_to_institution.send_generic_message("Hello Institution from consumer2").unwrap();

        institution.activate().unwrap();

        let consumer1_msgs = institution_to_consumer1.download_messages(None, None).unwrap();
        assert_eq!(consumer1_msgs.len(), 2);

        let consumer2_msgs = institution_to_consumer2.download_messages(None, None).unwrap();
        assert_eq!(consumer2_msgs.len(), 2);

        let consumer1_received_msgs = institution_to_consumer1.download_messages(Some(vec![MessageStatusCode::Received]), None).unwrap();
        assert_eq!(consumer1_received_msgs.len(), 1);

        let consumer1_reviewed_msgs = institution_to_consumer1.download_messages(Some(vec![MessageStatusCode::Reviewed]), None).unwrap();
        assert_eq!(consumer1_reviewed_msgs.len(), 1);
    }

    #[cfg(feature = "agency_v2")]
    #[test]
    fn test_update_agency_messages() {
        let _setup = SetupEmpty::init();
        let mut institution = Faber::setup();
        let mut consumer1 = Alice::setup();
        let (alice_to_faber, faber_to_alice) = create_connected_connections(&mut consumer1, &mut institution);

        faber_to_alice.send_generic_message("Hello 1").unwrap();
        faber_to_alice.send_generic_message("Hello 2").unwrap();
        faber_to_alice.send_generic_message("Hello 3").unwrap();

        thread::sleep(Duration::from_millis(1000));
        consumer1.activate().unwrap();

        let received = alice_to_faber.download_messages(Some(vec![MessageStatusCode::Received]), None).unwrap();
        assert_eq!(received.len(), 3);
        let uid = received[0].uid.clone();

        let reviewed = alice_to_faber.download_messages(Some(vec![MessageStatusCode::Reviewed]), None).unwrap();
        let reviewed_count_before = reviewed.len();

        let pairwise_did = alice_to_faber.pairwise_info().pw_did.clone();
        let message = serde_json::to_string(&vec![UIDsByConn { pairwise_did: pairwise_did.clone(), uids: vec![uid.clone()] }]).unwrap();
        update_agency_messages("MS-106", &message).unwrap();

        let received = alice_to_faber.download_messages(Some(vec![MessageStatusCode::Received]), None).unwrap();
        assert_eq!(received.len(), 2);

        let reviewed = alice_to_faber.download_messages(Some(vec![MessageStatusCode::Reviewed]), None).unwrap();
        let reviewed_count_after = reviewed.len();
        assert_eq!(reviewed_count_after, reviewed_count_before + 1);

        let specific_review = alice_to_faber.download_messages(Some(vec![MessageStatusCode::Reviewed]), Some(vec![uid.clone()])).unwrap();
        assert_eq!(specific_review[0].uid, uid);
    }
}

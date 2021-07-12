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

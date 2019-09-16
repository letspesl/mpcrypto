use crate::Error;

#[derive(Debug)]
pub enum SendType {
    Broadcast,
    ToPeer,
}

#[derive(Debug)]
pub enum ReceiveType {
    PollBroadcast,
    FromPeer,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct NetInfo {
    pub network_id: String,
    pub total_clients: usize,
    pub client_id: usize
}

pub trait Net {
    fn new(protocol_name: String, total_clients: usize, parties: Vec<String>) -> Self;

    fn send<T>(&self, send_type: SendType, path: &str, round: &str, data: T) -> Result<(), ()> where T: serde::ser::Serialize;
    fn receive(&self, receive_type: ReceiveType, path: &str, round: &str) -> Result<Vec<String>, Error>;

    fn get_info(&self) -> &NetInfo;
}
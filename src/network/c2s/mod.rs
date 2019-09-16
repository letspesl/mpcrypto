use reqwest::Client;
use std::{thread, time};
use super::traits::{SendType, ReceiveType, NetInfo, Net};
use crate::Error;

#[derive(Hash, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct TupleKey {
    pub first: String,
    pub second: String,
    pub third: String,
    pub fourth: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
    pub key: TupleKey,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: TupleKey,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct ClientToServer {
    pub client: Client,
    pub addr: String,
    pub retries: u64,
    pub retry_delay: u64,
    pub poll_delay: u64,
    pub info: NetInfo
}

impl ClientToServer {
    pub fn post<T>(&self, path: &str, body: T) -> Option<String>
    where
        T: serde::ser::Serialize,
    {
        for _i in 1..self.retries {
            let res = self.client
                .post(&format!("{}/{}", &self.addr, path))
                .json(&body)
                .send();
            if res.is_ok() {
                return Some(res.unwrap().text().unwrap());
            }
            thread::sleep(time::Duration::from_millis(self.retry_delay));
        }
        None
    }

    pub fn broadcast(
        &self,
        path: &str,
        round: &str,
        data: String
    ) -> Result<(), ()> {
        let key = TupleKey {
            first: self.info.client_id.to_string(),
            second: round.to_string(),
            third: self.info.network_id.clone(),
            fourth: "".to_string(),
        };
        let entry = Entry {
            key: key.clone(),
            value: data,
        };

        let res_body = &self.post(path, entry).unwrap();
        let answer: Result<(), ()> = serde_json::from_str(&res_body).unwrap();
        return answer;
    }

    pub fn sendp2p(
        &self,
        path: &str,
        round: &str,
        data: String
    ) -> Result<(), ()> {
        let (method, party_to): (&str, &str) = serde_json::from_str(&path).unwrap();
        let key = TupleKey {
            first: self.info.client_id.to_string(),
            second: round.to_string(),
            third: self.info.network_id.clone(),
            fourth: party_to.to_string(),
        };
        let entry = Entry {
            key: key.clone(),
            value: data,
        };

        let res_body = &self.post(method, entry).unwrap();
        let answer: Result<(), ()> = serde_json::from_str(&res_body).unwrap();
        return answer;
    }

    pub fn poll_for_broadcasts(
        &self,
        path: &str,
        round: &str
    ) -> Result<Vec<String>, Error> {
        let mut ans_vec = Vec::new();
        for i in 1..&self.info.total_clients + 1 {
            if i != self.info.client_id {
                let key = TupleKey {
                    first: i.to_string(),
                    second: round.to_string(),
                    third: self.info.network_id.clone(),
                    fourth: "".to_string(),
                };
                let index = Index { key };
                let mut success = false;
                for _i in 1..self.retries {
                    // add delay to allow the server to process request:
                    thread::sleep(time::Duration::from_millis(self.poll_delay));
                    let res_body = &self.post(path, index.clone()).unwrap();
                    let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                    if answer.is_ok() {
                        ans_vec.push(answer.unwrap().value);
                        println!("party {:?} {:?} read success", i, round);
                        success = true;
                        break;
                    }
                }
                if success == false {
                    return Err(Error::BadRequest);
                }
            }
        }

        Ok(ans_vec)
    }

    pub fn poll_for_p2p(
        &self,
        path: &str,
        round: &str
    ) -> Result<Vec<String>, Error> {
        let mut ans_vec = Vec::new();
        for i in 1..&self.info.total_clients + 1 {
            if i != self.info.client_id {
                let key = TupleKey {
                    first: i.to_string(),
                    second: round.to_string(),
                    third: self.info.network_id.clone(),
                    fourth: self.info.client_id.to_string(),
                };
                let index = Index { key };
                let mut success = false;
                for _i in 1..self.retries {
                    // add delay to allow the server to process request:
                    thread::sleep(time::Duration::from_millis(self.poll_delay));
                    let res_body = &self.post(path, index.clone()).unwrap();
                    let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                    if answer.is_ok() {
                        ans_vec.push(answer.unwrap().value);
                        println!("party {:?} {:?} read success", i, round);
                        success = true;
                        break;
                    }
                }
                if success == false {
                    return Err(Error::BadRequest);
                }
            }
        }

        Ok(ans_vec)
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u32,
    pub uuid: String,
}

impl Net for ClientToServer {
    fn new(protocol_name: String, total_clients: usize, parties: Vec<String>) -> ClientToServer {
        let mut net = ClientToServer {
            client: Client::new(),
            addr: parties[0].clone(),
            retries: 10,
            retry_delay: 250,
            poll_delay: 500,  
            info: NetInfo {
                network_id: String::new(),
                total_clients: total_clients,
                client_id: 0
            }
        };

        let key = TupleKey {
            first: "signup".to_string(),
            second: protocol_name.clone(),
            third: "".to_string(),
            fourth: "".to_string(),
        };

        let entry = Entry {
            key: key,
            value: total_clients.to_string()
        };

        let res_body = net.post("signup", &entry).unwrap();
        let result: Result<(PartySignup), ()> = serde_json::from_str(&res_body).unwrap();
        assert!(result.is_ok());

        let signup = result.unwrap();
        println!("{:?}", signup);

        net.info.client_id = signup.number as usize;
        net.info.network_id = signup.uuid;

        net
    }

    fn send<T>(&self, send_type: SendType, path: &str, round: &str, data: T) -> Result<(), ()> 
    where
        T: serde::ser::Serialize,
    {
        match send_type {
            SendType::Broadcast => {
                let body = serde_json::to_string(&data).unwrap();
                self.broadcast(path, round, body)
            },
            SendType::ToPeer => {
                let body = serde_json::to_string(&data).unwrap();
                self.sendp2p(path, round, body)
            },
        }
    }

    fn receive(&self, receive_type: ReceiveType, path: &str, round: &str) -> Result<Vec<String>, Error> 
    {
        match receive_type {
            ReceiveType::PollBroadcast => {
                self.poll_for_broadcasts(path, round)
            },
            ReceiveType::FromPeer => {
                self.poll_for_p2p(path, round)
            },
        }
    }
    
    fn get_info(&self) -> &NetInfo {
        &self.info
    }
}
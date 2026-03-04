use std::collections::{HashSet, HashMap};

use consensus::LargeField;
use lambdaworks_math::polynomial::Polynomial;
use types::Replica;

pub type Val = i64;


#[derive(Debug, Clone)]
pub struct BVState {
    pub bin_values: HashSet<Val>,                          // 已交付的值集合
    pub received_bval: HashMap<Val, HashSet<Replica>>,     // 每个值收到多少个 BVal
    pub has_echoed: HashSet<Val>,                          // 本节点是否已 echo 该值
}

#[derive(Debug, Clone)]
pub struct SBVState {
    pub bv: BVState,
    pub received_aux: HashMap<Val, HashSet<Replica>>,      // 收到的 Aux(val)
    pub view: Option<HashSet<Val>>,                        // 计算完成的 view（固定不变）
    pub has_sent_aux: bool,                                // 是否已发送 Aux（避免重复）
    pub received_auxsets: HashMap< Replica, HashSet<Val>>,
    pub auxset_checked: bool,
}

#[derive(Debug, Clone, Default)]
pub struct BAInstance {
    pub esti: Option<Val>,                                 // 当前 estimate，None 表示 ⊥
    pub current_round: usize,
    // pub sbv_stage0: SBVState,                              // 当前轮的 stage 0
    // pub sbv_stage1: Option<SBVState>,                      // 当前轮的 stage 1（还未启动时为 None）
}

impl BVState {
    pub fn new() -> Self {
        Self {
            bin_values: HashSet::new(),
            received_bval: HashMap::new(),
            has_echoed: HashSet::new(),
        }
    }

    /// 返回：(是否需要 echo 该值, 是否新交付了值)
    pub fn record_bval(&mut self, val: Val, sender: Replica, _n: usize, t: usize) -> (bool, bool) {
        let entry = self.received_bval.entry(val).or_insert_with(HashSet::new);
        let was_new = entry.insert(sender);

        if !was_new {
            return (false, false); // 重复消息
        }

        let mut need_echo = false;
        let mut new_delivered = false;

        // (t+1) 阈值 → 需要 echo（但只 echo 一次）
        if entry.len() == t+1 && !self.has_echoed.contains(&val) {
            self.has_echoed.insert(val);
            need_echo = true;
        }

        // (2t+1) 阈值 → 交付
        if entry.len() == 2 * t + 1 && !self.bin_values.contains(&val) {
            self.bin_values.insert(val);
            new_delivered = true;
        }

        (need_echo, new_delivered)
    }
}

impl SBVState {
    pub fn new() -> Self {
        Self {
            bv: BVState::new(),
            received_aux: HashMap::new(),
            view: None,
            has_sent_aux: false,
            received_auxsets: HashMap::new(),
            auxset_checked: false,
        }
    }

    /// BV 新交付值时调用，返回是否应该发送 Aux
    pub fn on_bv_new_delivered(&mut self) -> bool {
        if !self.bv.bin_values.is_empty() && !self.has_sent_aux {
            self.has_sent_aux = true;
            true
        } else {
            false
        }
    }

    /// 选择要发送的 Aux 值（论文说任意一个即可）
    pub fn choose_aux_value(&self) -> Option<Val> {
        self.bv.bin_values.iter().next().copied()
    }

    /// 记录 Aux，返回是否 view 已计算完成
    pub fn record_aux(&mut self, val: Val, sender: Replica, n: usize, t: usize) -> bool {

        let entry = self.received_aux.entry(val).or_insert_with(HashSet::new);
        let was_new = entry.insert(sender);
        if !was_new {
            return false;
        }

        if self.check_aux(val, n, t){
            return true;
        }

        false

    }
    pub fn check_aux(&mut self, val: Val, n: usize, t: usize) -> bool {
        // 只接受在 bin_values 中的值
        if !self.bv.bin_values.contains(&val) {
            return false;
        }

        // 检查是否所有值都达到了 (n-t) Aux
        if self.view.is_none() {
            let mut all_reached = true;
            for v in &self.bv.bin_values {
                let count = self.received_aux.get(v).map(|s| s.len()).unwrap_or(0);
                if count < n - t {
                    all_reached = false;
                    break;
                }
            }
            if all_reached {
                let view: HashSet<Val> = self.received_aux.keys().copied().collect();
                self.view = Some(view);
                return true;
            }
        }
        false
    }

    pub fn is_completed(&self) -> bool {
        self.view.is_some()
    }

    pub fn get_view(&self) -> HashSet<Val> {
        self.view.clone().unwrap_or_default()
    }
}







#[derive(Debug,Clone)]
pub struct RoundStateBin{
    // Map of Replica, and binary state of two values, their echos list and echo2 list, list of values for which echo1s were sent and echo2s list
    pub state: Vec<(Val,HashSet<Replica>,HashSet<Replica>,bool,bool)>,
    pub echo1vals: HashSet<Val>,
    pub echo2vals: Vec<Val>,
    pub echo3vals: HashMap<Replica,Val>,
    pub echo3sent: bool,
    pub termval: Option<Val>,

    pub num_nodes: usize,
    pub num_faults: usize,

    pub min_threshold: usize,
    pub high_threshold: usize,
}

impl RoundStateBin{

    pub fn to_target_type(msg:Val)->Val{
        msg
    }

    pub fn new_with_echo(msg: Val,echo_sender:Replica, num_faults: usize ,num_nodes: usize)-> RoundStateBin{
        let mut rnd_state = RoundStateBin{
            state:Vec::new(),
            echo1vals: HashSet::new(),
            echo2vals: Vec::new(),
            echo3vals: HashMap::default(),
            echo3sent:false,
            termval:None,

            num_nodes: num_nodes,
            num_faults: num_faults,

            min_threshold: num_faults+1,
            high_threshold: num_nodes - num_faults,
        };
        let parsed_bigint = Self::to_target_type(msg.clone());
        //let mut arr_state:Vec<(u64,HashSet<Replica>,HashSet<Replica>,bool,bool)> = Vec::new();
        let mut echo1_set = HashSet::new();
        echo1_set.insert(echo_sender);
        let echo2_set:HashSet<Replica>=HashSet::new();
        rnd_state.state.push((parsed_bigint,echo1_set,echo2_set,false,false));
        rnd_state
    }
}
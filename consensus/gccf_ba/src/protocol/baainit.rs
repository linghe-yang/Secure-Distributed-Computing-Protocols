use std::collections::HashSet;
use types::Replica;
use crate::Context;
use crate::msg::ProtMsg;
use crate::protocol::{BAInstance, SBVState, Val};

impl Context  {
    pub async fn start_ba(&mut self, instance_id: usize, baa_round: usize, term_val: Val, terminate: bool) {
        if self.terminated_rounds.contains(&instance_id){
            return;
        }
        if !terminate{
            log::debug!("Received request to start new round instance_id {} bround {}",instance_id,baa_round);
            // Restart next round with updated value
            self.broadcast(ProtMsg::BVal(term_val, self.myid, instance_id,baa_round, 0)).await;
        }
        else {
            // Find target proposal that was elected
            self.terminated_rounds.insert(instance_id);
            log::debug!("Terminating BA round {} for instance {}, broadcasting value {:?}",baa_round,instance_id,term_val);
            let _status = self.out_bin_ba_values.send((instance_id, term_val)).await;
            if _status.is_err(){
                log::error!("Failed to send BA value for instance {}",instance_id);
            }
        }
    }


    pub async fn process_b_val(
        &mut self,
        val: Val,
        sender: Replica,
        instance_id: usize,
        round: usize,
        stage: usize,  // 0 或 1
    ) {
        log::debug!("B_val for inst {} from {} in round {}, stage {} received",instance_id,sender,round,stage);
        let key = (instance_id, round, stage);
        let sbv = self.sbv_states.entry(key).or_insert_with(SBVState::new);

        let (need_echo, new_delivered) = sbv.bv.record_bval(
            val, sender, self.num_nodes, self.num_faults,
        );

        let mut msg_to_send = Vec::new();

        // 需要 echo → 广播 BVal（论文 Figure 1 行 05）
        if need_echo {
            msg_to_send.push(ProtMsg::BVal(val, self.myid, instance_id, round, stage));
        }

        // 新交付值 → 检查是否该发送 Aux
        if new_delivered && sbv.on_bv_new_delivered() {
            if let Some(w) = sbv.choose_aux_value() {
                msg_to_send.push(ProtMsg::Aux(w, instance_id, round, stage));
            }
        }

        let completed = sbv.check_aux(val, self.num_nodes, self.num_faults);
        let view = sbv.get_view();


        for msg in msg_to_send {
            self.broadcast(msg).await;
        }
        if completed {
            self.on_sbv_completed(instance_id, round, stage, &view).await;
        }

        if new_delivered && stage == 0 {
            self.check_auxset_completed(instance_id, round, stage).await;
        }
    }

    pub async fn process_aux(
        &mut self,
        val: Val,
        sender: Replica,
        instance_id: usize,
        round: usize,
        stage: usize,
    ) {
        log::debug!("B_aux for inst {} from {} in round {}, stage {} received",instance_id,sender,round,stage);
        let key = (instance_id, round, stage);

        let sbv = self.sbv_states.entry(key).or_insert_with(SBVState::new);
        let completed = sbv.record_aux(val, sender, self.num_nodes, self.num_faults);
        let view = sbv.get_view();
        if completed {
            self.on_sbv_completed(instance_id, round, stage, &view).await;
        }
    }

    pub async fn process_auxset(
        &mut self,
        view_from_sender: HashSet<Val>,
        sender: Replica,
        instance_id: usize,
        round: usize,
    ) {
        log::debug!("aux set for inst {} from {} in round {} received",instance_id,sender,round);
        // 只处理当前轮的 stage 0 对应的 AuxSet
        let key = (instance_id, round, 0);

        let sbv = self.sbv_states.entry(key).or_insert_with(SBVState::new);

        sbv.received_auxsets.entry(sender).or_insert(view_from_sender);

        self.check_auxset_completed(instance_id, round, 0).await;

        // let sbv = match self.sbv_states.get_mut(&key) {
        //     Some(s) => s,
        //     None => return, // 还没到这一步，忽略
        // };

        // 关键检查：收到的 view_from_sender 是否全部属于本地的 bin_values
        // （论文行 05 条件 (i)）
        // if !view_from_sender.is_subset(&sbv.bv.bin_values) {
        //     return; // 非法，忽略
        // }
        //
        // // 记录这个有效的 AuxSet
        // let received_auxsets = self.auxset_received.entry(key).or_insert_with(HashSet::new);
        // received_auxsets.insert(sender);
        //
        // // 检查是否已收到 (n - t) 个有效 AuxSet （论文行 05 条件 (ii)）
        // if received_auxsets.len() >= self.num_nodes - self.num_faults {
        //     // 计算 view[ri,1]：所有收到的有效 view_from_sender 的并集（实际可优化为交集更安全）
        //     // 但论文原文允许任意满足条件的集合，这里简单取第一个或并集
        //     // 最安全做法：取所有收到的 view 的交集（最保守）
        //     let mut view_ri_1: HashSet<Val> = sbv.bv.bin_values.clone();
        //     // 如果有多个，可遍历交集，这里简化：直接用第一个收到的（good case 足够）
        //     view_ri_1 = view_from_sender;
        //
        //     // 更新 esti （论文行 06-09）
        //     let new_esti = if view_ri_1.len() == 1 {
        //         view_ri_1.iter().next().copied()
        //     } else {
        //         None  // ⊥
        //     };
        //
        //     // 更新实例状态
        //     if let Some(inst) = self.instances.get_mut(&instance_id) {
        //         inst.esti = new_esti;
        //     }
        //
        //     // 启动第二阶段 SBV-Broadcast（stage 1）
        //     let stage1_key = (instance_id, round, 1);
        //     self.sbv_states.insert(stage1_key, SBVState::new());
        //
        //     // 用当前 esti 广播 BVal 启动 stage 1
        //     let bval_to_send = new_esti.unwrap_or(0); // ⊥ 时随便发一个，good case 不影响
        //     self.broadcast(ProtMsg::BVal(
        //         bval_to_send,
        //         self.myid,
        //         instance_id,
        //         round,
        //         1,  // stage = 1
        //     ))
        //         .await;
        // }
    }

    pub async fn check_auxset_completed(&mut self, instance_id: usize, round: usize, stage: usize) {
        let key = (instance_id, round, stage);
        let sbv = match self.sbv_states.get_mut(&key) {
            Some(s) => s,
            None => return,
        };
        if sbv.auxset_checked {
            return;
        }
        let mut valid_senders = HashSet::new();
        let mut valid_values: HashSet<Val> = HashSet::new();  // 用于计算 view_ri_1
        for (sender, view_from_sender) in &sbv.received_auxsets {
            if view_from_sender.is_subset(&sbv.bv.bin_values) {
                valid_senders.insert(*sender);
                for &val in view_from_sender {
                    valid_values.insert(val);
                }
            }
        }

        if valid_senders.len() >= self.num_nodes - self.num_faults {
            // 计算 view_ri_1：论文允许 "∃a set"，即任何满足 (i) 和 (ii) 的集合
            // 简单取所有合法值的集合（并集，确保 belong to bin_values）
            let view_ri_1 = valid_values.intersection(&sbv.bv.bin_values).copied().collect::<HashSet<Val>>();

            // 更新 esti （论文行 06-09）
            let new_esti = if view_ri_1.len() == 1 {
                view_ri_1.iter().next().copied()
            } else {
                None  // ⊥
            };

            let inst = self.instances.entry(instance_id).or_default();
            inst.esti = new_esti;
            // 更新实例状态
            // if let Some(inst) = self.instances.get_mut(&instance_id) {
            //     inst.esti = new_esti;
            // }

            // 标记已检查，避免重复
            sbv.auxset_checked = true;

            // 启动第二阶段 SBV-Broadcast（stage 1）
            let stage1_key = (instance_id, round, 1);
            self.sbv_states.entry(stage1_key).or_insert(SBVState::new());

            // 用当前 esti 广播 BVal 启动 stage 1
            let bval_to_send = new_esti.unwrap_or(2); // ⊥ 时发 0，good case 不影响
            self.broadcast(ProtMsg::BVal(
                bval_to_send,
                self.myid,
                instance_id,
                round,
                1,  // stage = 1
            ))
                .await;
        }

    }

    pub async fn on_sbv_completed(
        &mut self,
        instance_id: usize,
        round: usize,
        stage: usize,
        view: &HashSet<Val>,
    ) {
        if stage == 0 {
            self.on_sbv_stage0_completed(instance_id, round, view).await;
        } else {
            self.on_sbv_stage1_completed(instance_id, round, view).await;
        }
    }

    async fn on_sbv_stage0_completed(&mut self, instance_id: usize, round: usize, view: &HashSet<Val>) {
        // 广播 AuxSet[r](view)
        self.broadcast(ProtMsg::AuxSet(view.clone(), instance_id, round)).await;
        //
        // // 更新 esti（论文 Figure 3 行 06-09）
        // let new_esti = if view.len() == 1 {
        //     view.iter().next().copied()
        // } else {
        //     None
        // };
        //
        // // 更新实例状态
        // if let Some(inst) = self.instances.get_mut(&instance_id) {
        //     inst.esti = new_esti;
        // }
        //
        // // 启动 stage 1：用当前 esti 广播 BVal
        // let stage1_key = (instance_id, round, 1);
        // self.sbv_states.insert(stage1_key, SBVState::new());
        //
        // if let Some(esti_val) = new_esti {
        //     self.broadcast(ProtMsg::BVal(esti_val, self.myid, instance_id, round, 1)).await;
        // } else {
        //     // esti = ⊥ 时，论文中会广播 ⊥，但 BVal 是 binary，可约定广播 0 并在 view 中特殊处理
        //     // 简单起见：广播 0（good case 下不会走到这里）
        //     self.broadcast(ProtMsg::BVal(0, self.myid, instance_id, round, 1)).await;
        // }
    }

    /// stage 1 完成后：决定或进入下一轮
    async fn on_sbv_stage1_completed(&mut self, instance_id: usize, round: usize, view: &HashSet<Val>) {
        if view.len() == 1 {
            let v = *view.iter().next().unwrap();
            // 论文行 12：单值且 ≠ ⊥ → decide
            self.start_ba(instance_id, round, v, true).await;
        } else {
            unreachable!()
        }
    }
}
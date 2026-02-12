use std::env;
use std::path::PathBuf;

use coset_bls12_381::BlsScalar;
use coset_cdf::{
    BaseConfig, Config, EncodableConstraint, EncodableSource, EncodableWitness,
    Encoder, EncoderContextFileProvider, Polynomial, Selectors, WiredWitnesses,
};

use crate::composer::{Constraint, Selector, WiredWitness, Witness};
use crate::runtime::RuntimeEvent;

#[derive(Debug, Clone)]
pub(crate) struct Debugger {
    witnesses: Vec<(EncodableSource, Witness, BlsScalar)>,
    constraints: Vec<(EncodableSource, Constraint)>,
}

impl Debugger {
    /// 解析当前调用栈，定位触发事件的源代码位置。
    /// 该函数会过滤掉运行时与标准库帧，只保留业务侧最相关的调用点。
    /// 若无法解析有效位置，则返回默认源信息占位。
    fn resolve_caller() -> EncodableSource {
        let mut source = None;

        backtrace::trace(|frame| {
            backtrace::resolve_frame(frame, |symbol| {
                if symbol
                    .name()
                    .map(|symbol_name| symbol_name.to_string())
                    .filter(|name| !name.starts_with("backtrace::"))
                    .filter(|name| !name.starts_with("coset_plonk::"))
                    .filter(|name| !name.starts_with("core::"))
                    .filter(|name| !name.starts_with("std::"))
                    .is_some()
                {
                    if let Some(path) = symbol.filename() {
                        let line = symbol.lineno().unwrap_or_default() as u64;
                        let col = symbol.colno().unwrap_or_default() as u64;
                        let path = path
                            .canonicalize()
                            .unwrap_or_default()
                            .display()
                            .to_string();

                        source.replace(EncodableSource::new(line, col, path));
                    }
                }
            });

            source.is_none()
        });

        source.unwrap_or_default()
    }

    /// 将已收集的 witness/constraint 事件写出为 CDF 调试文件。
    /// 输出路径由环境变量 `CDF_OUTPUT` 指定；未设置时静默跳过。
    /// 该过程会把运行时数据转为可视化友好的编码结构，便于离线排障。
    fn write_output(&self) {
        let path = match env::var("CDF_OUTPUT") {
            Ok(path) => PathBuf::from(path),
            Err(env::VarError::NotPresent) => return (),
            Err(env::VarError::NotUnicode(_)) => {
                eprintln!("the provided `CDF_OUTPUT` isn't valid unicode");
                return ();
            }
        };

        let witnesses =
            self.witnesses.iter().map(|(source, witness, value)| {
                let witness_index = witness.index();
                let value = value.to_bytes().into();
                let source = source.clone();

                EncodableWitness::new(witness_index, None, value, source)
            });

        let constraints = self.constraints.iter().enumerate().map(
            |(id, (source, constraint))| {
                let source = source.clone();

                let multiplication_selector =
                    constraint.coeff(Selector::Multiplication);
                let left_selector = constraint.coeff(Selector::Left);
                let right_selector = constraint.coeff(Selector::Right);
                let output_selector = constraint.coeff(Selector::Output);
                let fourth_selector = constraint.coeff(Selector::Fourth);
                let constant_selector = constraint.coeff(Selector::Constant);
                let public_input_selector =
                    constraint.coeff(Selector::PublicInput);
                let arithmetic_selector =
                    constraint.coeff(Selector::Arithmetic);
                let logic_selector = constraint.coeff(Selector::Logic);
                let range_selector = constraint.coeff(Selector::Range);
                let variable_group_add_selector =
                    constraint.coeff(Selector::GroupAddVariableBase);
                let fixed_group_add_selector =
                    constraint.coeff(Selector::GroupAddFixedBase);

                let witnesses = WiredWitnesses {
                    a: constraint.witness(WiredWitness::A).index(),
                    b: constraint.witness(WiredWitness::B).index(),

                    o: constraint.witness(WiredWitness::C).index(),
                    d: constraint.witness(WiredWitness::D).index(),
                };

                let left_witness_value = self
                    .witnesses
                    .get(witnesses.a)
                    .map(|(_, _, value)| *value)
                    .unwrap_or_default();

                let right_witness_value = self
                    .witnesses
                    .get(witnesses.b)
                    .map(|(_, _, value)| *value)
                    .unwrap_or_default();

                let output_witness_value = self
                    .witnesses
                    .get(witnesses.o)
                    .map(|(_, _, value)| *value)
                    .unwrap_or_default();

                let fourth_witness_value = self
                    .witnesses
                    .get(witnesses.d)
                    .map(|(_, _, value)| *value)
                    .unwrap_or_default();

                let evaluation = multiplication_selector
                    * left_witness_value
                    * right_witness_value
                    + left_selector * left_witness_value
                    + right_selector * right_witness_value
                    + output_selector * output_witness_value
                    + fourth_selector * fourth_witness_value
                    + constant_selector
                    + public_input_selector;

                let evaluation = evaluation == BlsScalar::zero();

                let selectors = Selectors {
                    qm: multiplication_selector.to_bytes().into(),
                    ql: left_selector.to_bytes().into(),
                    qr: right_selector.to_bytes().into(),
                    qo: output_selector.to_bytes().into(),

                    qd: fourth_selector.to_bytes().into(),
                    qc: constant_selector.to_bytes().into(),
                    pi: public_input_selector.to_bytes().into(),
                    qarith: arithmetic_selector.to_bytes().into(),
                    qlogic: logic_selector.to_bytes().into(),
                    qrange: range_selector.to_bytes().into(),
                    qgroup_variable: variable_group_add_selector
                        .to_bytes()
                        .into(),
                    qfixed_add: fixed_group_add_selector.to_bytes().into(),
                };

                let polynomial =
                    Polynomial::new(selectors, witnesses, evaluation);

                EncodableConstraint::new(id, polynomial, source)
            },
        );

        if let Err(e) = Config::load()
            .and_then(|config| {
                Encoder::init_file(config, witnesses, constraints, &path)
            })
            .and_then(|mut c| {
                c.write_all(EncoderContextFileProvider::default())
            })
        {
            eprintln!(
                "failed to output CDF file to '{}': {}",
                path.display(),
                e
            );
        }
    }

    /// 创建空调试器实例。
    /// 新实例不包含任何事件记录，可在运行时按事件逐步填充。
    /// 该构造通常由 `Runtime` 在 `debug` 特性下自动调用。
    pub(crate) fn new() -> Self {
        Self {
            witnesses: Vec::new(),
            constraints: Vec::new(),
        }
    }

    /// 处理一条运行时事件并更新调试状态。
    /// witness 与 constraint 事件会被缓存，`ProofFinished` 事件触发最终落盘。
    /// 该接口是 Runtime 向调试模块传递状态的唯一入口。
    pub(crate) fn event(&mut self, event: RuntimeEvent) {
        match event {
            RuntimeEvent::WitnessAppended { witness, value } => {
                self.witnesses
                    .push((Self::resolve_caller(), witness, value));
            }

            RuntimeEvent::ConstraintAppended { constraint } => {
                self.constraints.push((Self::resolve_caller(), constraint));
            }

            RuntimeEvent::ProofFinished => {
                self.write_output();
            }
        }
    }
}

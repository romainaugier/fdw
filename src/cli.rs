use std::collections::HashMap;

/*
 * CLI Argument
 */
#[derive(Debug, Clone)]
pub enum CLIArgType {
    String,
    Int,
    Float,
    Bool,
}

impl Default for CLIArgType {
    fn default() -> Self {
        return CLIArgType::String;
    }
}

/*
 * TODO: implement append and count actions
 */

#[derive(Debug, Clone)]
pub enum CLIArgAction {
    Store,
    StoreTrue,
    StoreFalse,
}

impl Default for CLIArgAction {
    fn default() -> Self {
        return CLIArgAction::Store;
    }
}

#[allow(dead_code)]
#[derive(Default, Clone, Debug)]
struct CLIArg {
    arg_name: &'static str,
    arg_short_name: Option<&'static str>,
    arg_type: CLIArgType,
    arg_action: CLIArgAction,
    arg_value: String,
}

impl CLIArg {
    fn new(
        arg_name: &'static str,
        arg_short_name: Option<&'static str>,
        arg_type: CLIArgType,
        arg_action: CLIArgAction,
    ) -> CLIArg {
        return CLIArg {
            arg_name: arg_name,
            arg_short_name: arg_short_name,
            arg_type: arg_type,
            arg_action: arg_action,
            arg_value: String::default(),
        };
    }
}

/*
 * CLI Parser
 */
#[derive(Default, Clone, Debug)]
pub struct CLIParser {
    args: HashMap<&'static str, CLIArg>,
    short_names: HashMap<&'static str, &'static str>,
}

impl CLIParser {
    pub fn new() -> CLIParser {
        return CLIParser::default();
    }

    pub fn add_argument(
        &mut self,
        arg_name: &'static str,
        arg_short_name: Option<&'static str>,
        arg_type: CLIArgType,
        arg_action: CLIArgAction,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.args.contains_key(arg_name) {
            return Err("CLIParser already contains argument".into());
        }

        self.args.insert(
            arg_name,
            CLIArg::new(arg_name, arg_short_name, arg_type, arg_action),
        );

        if arg_short_name.is_some() {
            self.short_names.insert(arg_short_name.unwrap(), arg_name);
        }

        return Ok(());
    }

    pub fn parse(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let args = std::env::args();

        if args.len() == 1 {
            return Ok(());
        }

        /*
         * TODO: add short_name in parsing
         */

        for arg in args.skip(1).into_iter() {
            let first_eq = arg.find("=").unwrap_or(usize::max_value());

            if first_eq != usize::max_value() {
                let arg_split = arg
                    .split_once("=")
                    .expect("Can't find any '=' in the argument but should");

                let arg_name = arg_split.0.trim_matches('-');
                let arg_value = arg_split.1;

                let arg = self
                    .args
                    .get_mut(arg_name)
                    .expect("Undeclared argument parsed in command-line arguments");

                arg.arg_value = arg_value.to_string();
            } else {
                let arg = self
                    .args
                    .get_mut(arg.as_str().trim_matches('-'))
                    .expect("Undeclared argument parsed in command-line arguments");

                match arg.arg_action {
                    CLIArgAction::Store => {
                        return Err("Cannot use action Store on argument that has not value".into());
                    }
                    CLIArgAction::StoreTrue => {
                        arg.arg_value = "true".to_string();
                    }
                    CLIArgAction::StoreFalse => {
                        arg.arg_value = "false".to_string();
                    }
                }
            }
        }

        return Ok(());
    }

    pub fn get_argument_as_i64(&self, arg_name: &str) -> Result<i64, Box<dyn std::error::Error>> {
        let arg = self.args.get(arg_name).expect("Cannot find argument");

        let res = arg.arg_value.parse::<i64>();

        match res {
            Ok(x) => return Ok(x),
            Err(x) => return Err(x.into()),
        }
    }

    pub fn get_argument_as_f64(&self, arg_name: &str) -> Result<f64, Box<dyn std::error::Error>> {
        let arg = self.args.get(arg_name).expect("Cannot find argument");

        let res = arg.arg_value.parse::<f64>();

        match res {
            Ok(x) => return Ok(x),
            Err(x) => return Err(x.into()),
        }
    }

    pub fn get_argument_as_bool(&self, arg_name: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let arg = self.args.get(arg_name).expect("Cannot find argument");

        return Ok(matches!(
            arg.arg_value.to_lowercase().as_str(),
            "1" | "true" | "yes" | "on" | "t" | "y"
        ));
    }

    pub fn get_argument_as_string(
        &self,
        arg_name: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let arg = self.args.get(arg_name).expect("Cannot find argument");

        return Ok(arg.arg_value.to_string());
    }
}

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{ADMIN, SCORES, TOKEN_SCORES};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;

use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;
use cw_utils::maybe_addr;

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:counter";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    //setup admin
    let api = deps.api;
    ADMIN.set(deps, maybe_addr(api, msg.admin)?)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::SetScore {
            address_to_set,
            score,
        } => try_set_score(deps, info, address_to_set, score),
        ExecuteMsg::SetScoreWithToken {
            address_to_set,
            token,
            score,
        } => try_set_score_with_token(deps, info, address_to_set, token, score),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetScore { address } => {
            let valid_address = deps.api.addr_validate(&address)?;
            let raw_entry = SCORES.may_load(deps.storage, &valid_address)?;
            to_binary(&raw_entry)
        }
        QueryMsg::GetAdmin {} => to_binary(&ADMIN.get(deps)?),
        QueryMsg::GetTokenScore { address, token } => {
            let valid_address = deps.api.addr_validate(&address)?;
            let raw_entry = TOKEN_SCORES.may_load(deps.storage, (&valid_address, token))?;
            to_binary(&raw_entry)
        }
    }
}

pub fn try_set_score(
    deps: DepsMut,
    info: MessageInfo,
    address_to_set: String,
    score: u8,
) -> Result<Response, ContractError> {
    let valid_address_to_set = deps.api.addr_validate(&address_to_set)?;
    if ADMIN.is_admin(deps.as_ref(), &info.sender)? {
        SCORES.update(
            deps.storage,
            &valid_address_to_set,
            |_curr_score| -> StdResult<u8> { Ok(score) },
        )?;
    } else {
        return Err(ContractError::Unauthorized {});
    }

    Ok(Response::new().add_attribute("method", "try_set_score"))
}

pub fn try_set_score_with_token(
    deps: DepsMut,
    info: MessageInfo,
    address_to_set: String,
    token: String,
    score: u8,
) -> Result<Response, ContractError> {
    let valid_address_to_set = deps.api.addr_validate(&address_to_set)?;

    if ADMIN.is_admin(deps.as_ref(), &info.sender)? {
        TOKEN_SCORES.update(
            deps.storage,
            (&valid_address_to_set, token),
            |_curr_score| -> StdResult<u8> { Ok(score) },
        )?;
    } else {
        return Err(ContractError::Unauthorized {});
    }

    Ok(Response::new().add_attribute("method", "try_set_score_with_token"))
}
#[cfg(test)]
mod tests {

    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, from_binary};

    //
    #[test]
    fn proper_initialization() {
        //setup
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            admin: Some(String::from("VikChawla")),
        };
        let info = mock_info("VikChawla", &coins(2, "token"));
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        //no errors in instatiation
        assert_eq!(0, res.messages.len());

        //query to see if we get correct admin back
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetAdmin {}).unwrap();
        let address: String = from_binary(&res).unwrap();
        assert_eq!(address, "VikChawla");
    }

    #[test]
    fn set_score_and_update() {
        //setup
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            admin: Some(String::from("VikChawla")),
        };
        let info = mock_info("VikChawla", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        let info = mock_info("VikChawla", &coins(2, "token"));

        //Set score for Vitalik to 60
        let _res = execute(
            deps.as_mut(),
            mock_env(),
            info,
            ExecuteMsg::SetScore {
                address_to_set: String::from("Vitalik"),
                score: 60,
            },
        )
        .unwrap();

        let info = mock_info("VikChawla", &coins(2, "token"));

        //Set score for Satoshi to 100 - ability to store several addresses
        let _res = execute(
            deps.as_mut(),
            mock_env(),
            info,
            ExecuteMsg::SetScore {
                address_to_set: String::from("Satoshi"),
                score: 90,
            },
        )
        .unwrap();

        //query Vitalik's score
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetScore {
                address: String::from("Vitalik"),
            },
        )
        .unwrap();
        let score: u8 = from_binary(&res).unwrap();

        //validate that Vitalik's score is 60
        assert_eq!(score, 60);

        //Now update Vitalik's score to 90
        let info = mock_info("VikChawla", &coins(2, "token"));
        let _res = execute(
            deps.as_mut(),
            mock_env(),
            info,
            ExecuteMsg::SetScore {
                address_to_set: String::from("Vitalik"),
                score: 90,
            },
        )
        .unwrap();

        //query Vitalik's score
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetScore {
                address: String::from("Vitalik"),
            },
        )
        .unwrap();
        let score: u8 = from_binary(&res).unwrap();

        //validate that Vitalik's score is 90
        assert_eq!(score, 90);
    }

    #[test]
    fn admin_restrictions() {
        //setup
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            admin: Some(String::from("VikChawla")),
        };
        let info = mock_info("VikChawla", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        //create unauthorized user info
        let info = mock_info("Sifu", &coins(2, "token"));

        //Sifu tries to set a score for himself
        let res = execute(
            deps.as_mut(),
            mock_env(),
            info,
            ExecuteMsg::SetScore {
                address_to_set: String::from("Sifu"),
                score: 60,
            },
        );

        //Validate that Unathorized error was thrown
        assert!(matches!(res, Err(ContractError::Unauthorized {})));
    }

    //Bonus Tests
    #[test]
    fn set_token_scores_and_update() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            admin: Some(String::from("VikChawla")),
        };
        let info = mock_info("VikChawla", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        let info = mock_info("VikChawla", &coins(2, "token"));

        //Set Vitalik's ETH score to 100
        let _res = execute(
            deps.as_mut(),
            mock_env(),
            info,
            ExecuteMsg::SetScoreWithToken {
                address_to_set: String::from("Vitalik"),
                token: String::from("Eth"),
                score: 100,
            },
        )
        .unwrap();

        //Query Vitalik's Eth Score
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetTokenScore {
                address: String::from("Vitalik"),
                token: String::from("Eth"),
            },
        )
        .unwrap();

        let score: u8 = from_binary(&res).unwrap();

        //validate that Vitalik's score is 100
        assert_eq!(score, 100);

        let info = mock_info("VikChawla", &coins(2, "token"));

        //Set Vitalik's UST score - ability for an address to have multiple different token scores
        let _res = execute(
            deps.as_mut(),
            mock_env(),
            info,
            ExecuteMsg::SetScoreWithToken {
                address_to_set: String::from("Vitalik"),
                token: String::from("UST"),
                score: 60,
            },
        )
        .unwrap();

        //Query Vitalik's Eth Score
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetTokenScore {
                address: String::from("Vitalik"),
                token: String::from("UST"),
            },
        )
        .unwrap();

        let score: u8 = from_binary(&res).unwrap();

        //Validate that Vitalik's score is 60
        assert_eq!(score, 60);
    }
}

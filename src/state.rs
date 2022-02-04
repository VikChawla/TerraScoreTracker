use cosmwasm_std::Addr;
use cw_controllers::Admin;
use cw_storage_plus::Map;

//assuming no negative scores and 100 is the highest score
pub const SCORES: Map<&Addr, u8> = Map::new("scores");

//Using Admin Controller
pub const ADMIN: Admin = Admin::new("admin");

//assuming no negative scores and 100 is the highest score
pub const TOKEN_SCORES: Map<(&Addr, String), u8> = Map::new("token_scores");

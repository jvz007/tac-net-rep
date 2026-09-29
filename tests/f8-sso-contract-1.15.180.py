#!/usr/bin/env python3
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
text = (ROOT / 'framwork/tec_tac/contracts.py').read_text(encoding='utf-8')
assert 'ui.public.sso-providers' in text
assert 'Core owns the browser callback and token-completion boundary' in text
assert 'SSO provider modules may initiate sign-in only' in text
assert '/account/provider/callback' in text
assert 'public modules only initiate the provider redirect and never receive Tactical credentials or access tokens' in text
print('F8 SSO public contract 1.15.180: PASS')

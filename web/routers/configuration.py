from fastapi import APIRouter, HTTPException

from netchecker_config import (
    clear_overrides,
    default_config,
    effective_config,
    save_overrides,
    user_overrides,
)

router = APIRouter(prefix="/api/configuration", tags=["Configuration"])


@router.get("")
def read_configuration():
    return {
        "defaults": default_config(),
        "overrides": user_overrides(),
        "effective": effective_config(),
    }


@router.put("")
def write_configuration(payload: dict):
    try:
        overrides = save_overrides(payload)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except RuntimeError as error:
        raise HTTPException(status_code=500, detail=str(error)) from error
    return {
        "defaults": default_config(),
        "overrides": overrides,
        "effective": effective_config(),
    }


@router.delete("")
def reset_configuration():
    clear_overrides()
    return {
        "defaults": default_config(),
        "overrides": {},
        "effective": effective_config(),
    }

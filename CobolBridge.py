from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import subprocess
import json
import hashlib
import datetime
import logging
import os

# Configuração básica de logging (arquivo seguro)
LOG_FILE = "cobol_api_audit.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# FastAPI app
app = FastAPI(title="COBOL API Wrapper Seguro - Banco XYZ")

# Modelo de dados para requisição
class AccountRequest(BaseModel):
    account_number: str
    balance: float
    operation_type: str  # "interest", "fee"

# Chave de API simples (substituir por OAuth2 em produção)
API_KEY = os.getenv("COBOL_API_KEY", "SECRET123")

@app.post("/calculate")
def calculate(account: AccountRequest, x_api_key: str = Header(...), user_id: str = Header(...)):
    
    # --- Identity: validação da chave de API ---
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="API Key inválida")

    try:
        # --- Preparar input COBOL ---
        cobol_input = f"{account.account_number},{account.balance},{account.operation_type}"

        # --- Availability: executar COBOL com timeout ---
        result = subprocess.run(
            ["./cobol_program", cobol_input],
            capture_output=True,
            text=True,
            check=True,
            timeout=10  # segundos
        )

        # --- Integrity: validar retorno ---
        output_value = float(result.stdout.strip())
        if not (0 <= output_value <= 100000):  # limite realista
            raise HTTPException(status_code=500, detail="Valor calculado inválido")

        # --- Non-repudiation: gerar registro de auditoria ---
        timestamp = datetime.datetime.utcnow().isoformat()
        result_hash = hashlib.sha256(str(output_value).encode()).hexdigest()
        audit_record = {
            "timestamp": timestamp,
            "user_id": user_id,
            "account_number": account.account_number,
            "operation_type": account.operation_type,
            "calculated_value": output_value,
            "result_hash": result_hash,
        }
        logging.info(json.dumps(audit_record))  # salvar log seguro

        # --- Retornar resposta ---
        return {
            "account_number": account.account_number,
            "operation_type": account.operation_type,
            "calculated_value": output_value,
            "audit_hash": result_hash
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Tempo de execução do COBOL excedido")
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Erro ao executar COBOL: {e.stderr}")
    except ValueError:
        raise HTTPException(status_code=500, detail="Retorno inválido do COBOL")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro inesperado: {str(e)}")

# --- Observações de Confidentiality ---
# 1. Rodar com HTTPS (uvicorn: --ssl-keyfile / --ssl-certfile)
# 2. Evitar log de dados sensíveis (somente hash do resultado)
# 3. Variáveis sensíveis (API_KEY) via environment variables

# Executar localmente: uvicorn cobol_api_secure:app --host 0.0.0.0 --port 443 --ssl-keyfile=key.pem --ssl-certfile=cert.pem

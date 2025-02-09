import os
import sys
import requests
import time
import matplotlib.pyplot as plt
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Button, Static
from textual.containers import Container, Vertical

# Classe principal do aplicativo
class FortiSecOps(App):
    CSS_PATH = "styles.tcss"  # Estilo para tornar a UI profissional

    def compose(self) -> ComposeResult:
        """Monta a interface principal do programa."""
        yield Header()
        yield Footer()
        yield Container(
            Vertical(
                Static("FORTISECOPS - Suíte de Segurança Fortinet", classes="title"),
                Button("Monitoramento e Diagnóstico", id="monitoramento"),
                Button("Segurança e Firewall", id="seguranca"),
                Button("VPN e Acesso Remoto", id="vpn"),
                Button("Relatórios e Análises", id="relatorios"),
                Button("Automação e Gestão", id="automacao"),
                Button("Sair", id="sair", variant="error")
            ),
            classes="main-container"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Define ações quando botões são pressionados."""
        button_id = event.button.id
        if button_id == "monitoramento":
            self.run_monitoramento()
        elif button_id == "seguranca":
            self.run_seguranca()
        elif button_id == "vpn":
            self.run_vpn()
        elif button_id == "relatorios":
            self.run_relatorios()
        elif button_id == "automacao":
            self.run_automacao()
        elif button_id == "sair":
            self.exit()

    def run_automacao(self):
        """Executa funções de automação, incluindo backup e restauração de configuração."""
        url_backup = "https://fortigate/api/v2/monitor/system/config/backup"
        url_restore = "https://fortigate/api/v2/monitor/system/config/restore"
        headers = {"Authorization": "Bearer SEU_TOKEN_AQUI"}
        
        # Backup automático da configuração
        try:
            response = requests.get(url_backup, headers=headers, verify=False)
            if response.status_code == 200:
                with open("backup_fortigate.conf", "wb") as file:
                    file.write(response.content)
                print("✅ Backup realizado com sucesso!")
            else:
                print("❌ Erro ao realizar backup.")
        except Exception as e:
            print(f"Erro ao realizar backup: {e}")
        
        # Simulação de restauração automática
        if os.path.exists("backup_fortigate.conf"):
            with open("backup_fortigate.conf", "rb") as file:
                files = {"file": file}
                try:
                    response = requests.post(url_restore, headers=headers, files=files, verify=False)
                    if response.status_code == 200:
                        print("✅ Restauração concluída com sucesso!")
                    else:
                        print("❌ Erro na restauração da configuração.")
                except Exception as e:
                    print(f"Erro ao restaurar backup: {e}")

if __name__ == "__main__":
    FortiSecOps().run()

import os
import subprocess
import requests
from tkinter import Tk, Label, Button, Text, Scrollbar

# Função para obter as informações do sistema
def get_system_info():
    system_info = {}
    
    # Obtendo a versão do Kernel
    system_info['Kernel'] = subprocess.check_output("uname -r", shell=True).decode().strip()
    
    # Obtendo a versão da distribuição
    try:
        dist = subprocess.check_output("lsb_release -a", shell=True).decode()
        for line in dist.split("\n"):
            if "Description" in line:
                system_info['Distribuição'] = line.split(":")[1].strip()
    except subprocess.CalledProcessError:
        system_info['Distribuição'] = 'Não disponível'
    
    # Listando pacotes instalados (para Debian/Ubuntu)
    system_info['Pacotes'] = subprocess.check_output("dpkg -l", shell=True).decode().split("\n")[:10]  # Limitar a quantidade para exemplo
    
    return system_info

# Função para verificar vulnerabilidades no NVD (Exemplo simples)
def check_vulnerabilities(system_info):
    cve_base_url = "https://services.nvd.nist.gov/rest/json/cve/1.0"
    vulnerabilities = []
    
    # Para cada pacote instalado, verificar por vulnerabilidades
    for package in system_info['Pacotes']:
        if package:  # Ignorar linhas vazias
            package_name = package.split()[1]
            url = f"{cve_base_url}?cpeMatchString=cpe:2.3:a:{package_name}"
            
            # Consultar a base de dados NVD
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                if 'result' in data and 'CVE_Items' in data['result']:
                    for item in data['result']['CVE_Items']:
                        if 'cve' in item:
                            vulnerabilities.append({
                                'CVE': item['cve']['CVE_data_meta']['ID'],
                                'Descricao': item['cve']['description']['description_data'][0]['value']
                            })
    return vulnerabilities

# Função para sugerir correções com base nas vulnerabilidades encontradas
def suggest_corrections(vulnerabilities):
    suggestions = []
    for vuln in vulnerabilities:
        suggestions.append(f"Correção sugerida para {vuln['CVE']}: {vuln['Descricao']}")
    return suggestions

# Função principal para a interface gráfica
def main():
    root = Tk()
    root.title("Analisador de Vulnerabilidades - Sistema Linux")

    # Obter informações do sistema
    system_info = get_system_info()

    # Exibir informações do sistema
    Label(root, text="Informações do Sistema", font=("Arial", 14)).pack()
    info_text = Text(root, height=10, width=100)
    info_text.insert("1.0", f"Kernel: {system_info['Kernel']}\nDistribuição: {system_info['Distribuição']}\n")
    info_text.insert("end", "Pacotes instalados:\n")
    info_text.insert("end", "\n".join(system_info['Pacotes']))
    info_text.pack()

    # Verificar vulnerabilidades
    vulnerabilities = check_vulnerabilities(system_info)

    # Exibir vulnerabilidades detectadas
    Label(root, text="Vulnerabilidades Detectadas", font=("Arial", 14)).pack()
    vuln_text = Text(root, height=10, width=100)
    if vulnerabilities:
        for vuln in vulnerabilities:
            vuln_text.insert("end", f"CVE: {vuln['CVE']}\nDescrição: {vuln['Descricao']}\n\n")
    else:
        vuln_text.insert("end", "Nenhuma vulnerabilidade encontrada.\n")
    vuln_text.pack()

    # Sugerir correções
    corrections = suggest_corrections(vulnerabilities)
    
    Label(root, text="Correções Sugeridas", font=("Arial", 14)).pack()
    correction_text = Text(root, height=10, width=100)
    if corrections:
        correction_text.insert("end", "\n".join(corrections))
    else:
        correction_text.insert("end", "Nenhuma correção sugerida.\n")
    correction_text.pack()

    root.mainloop()

if __name__ == "__main__":
    main()

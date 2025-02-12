import curses
import time

# Estrutura do menu
MENU_PRINCIPAL = [
    "Segurança de Perímetro e Proteção de Rede",
    "Proteção de Endpoints e Identidade",
    "Segurança de Aplicações e Dados",
    "Inteligência Artificial e Automação em Segurança",
    "Monitoramento e Análise de Segurança",
    "Simulação e Prevenção de Ameaças",
    "Conectividade Segura e Infraestrutura",
    "Planejamento, Gestão e Implementação de Segurança",
    "Sair do Programa"
]

# Estrutura de submenus
SUBMENUS = {
    "Segurança de Perímetro e Proteção de Rede": [
        {"name": "FortiGate NGFW", "status": "Ativo"},
        {"name": "FortiDDoS", "status": "Inativo"},
        {"name": "FortiNAC", "status": "Ativo"},
        {"name": "FortiSwitch", "status": "Ativo"}
    ],
    "Proteção de Endpoints e Identidade": [
        {"name": "FortiEDR", "status": "Ativo"},
        {"name": "FortiInsight", "status": "Inativo"},
        {"name": "FortiAuthenticator", "status": "Ativo"},
        {"name": "FortiToken", "status": "Ativo"}
    ]
}

def exibir_menu(stdscr, menu, titulo):
    curses.curs_set(0)
    stdscr.clear()
    stdscr.refresh()
    selecionado = 0
    while True:
        stdscr.clear()
        stdscr.addstr(0, 2, titulo, curses.A_BOLD)
        for idx, item in enumerate(menu):
            if idx == selecionado:
                stdscr.attron(curses.color_pair(1))
                stdscr.addstr(idx + 2, 2, item)
                stdscr.attroff(curses.color_pair(1))
            else:
                stdscr.addstr(idx + 2, 2, item)
        stdscr.addstr(len(menu) + 3, 2, "[Pressione 'q' para sair do menu]")
        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP and selecionado > 0:
            selecionado -= 1
        elif key == curses.KEY_DOWN and selecionado < len(menu) - 1:
            selecionado += 1
        elif key == ord('\n'):
            return menu[selecionado]
        elif key == ord('q'):
            return "Sair do Programa"

def exibir_submenu(stdscr, opcao):
    if opcao not in SUBMENUS:
        return
    submenu = SUBMENUS[opcao]
    stdscr.clear()
    selecionado = 0
    while True:
        stdscr.clear()
        stdscr.addstr(0, 2, f"{opcao} - Escolha um serviço (Pressione 't' para ativar/desativar):", curses.A_BOLD)
        for idx, item in enumerate(submenu):
            cor = curses.color_pair(2) if item["status"] == "Ativo" else curses.color_pair(3)
            if idx == selecionado:
                stdscr.attron(curses.color_pair(1))
            stdscr.attron(cor)
            stdscr.addstr(idx + 2, 2, f"{item['name']} ({item['status']})")
            stdscr.attroff(cor)
            if idx == selecionado:
                stdscr.attroff(curses.color_pair(1))
        stdscr.addstr(len(submenu) + 3, 2, "[Pressione 'b' para voltar]")
        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP and selecionado > 0:
            selecionado -= 1
        elif key == curses.KEY_DOWN and selecionado < len(submenu) - 1:
            selecionado += 1
        elif key == ord('t'):
            submenu[selecionado]["status"] = "Inativo" if submenu[selecionado]["status"] == "Ativo" else "Ativo"
        elif key == ord('b'):
            break

def atualizar_status():
    for categoria in SUBMENUS:
        for item in SUBMENUS[categoria]:
            item["status"] = "Ativo" if time.time() % 2 < 1 else "Inativo"  # Simulação de status dinâmico

def main(stdscr):
    curses.start_color()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
    
    while True:
        atualizar_status()
        escolha = exibir_menu(stdscr, MENU_PRINCIPAL, "FortiNavigator - Menu Principal")
        if escolha == "Sair do Programa":
            break
        exibir_submenu(stdscr, escolha)
        time.sleep(1)  # Atualização automática do status

curses.wrapper(main)

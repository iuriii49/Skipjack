# Skipjack
Nome: Iuri Milagre Caldeira Brant
Nome: Lucas de Miranda Martins


Instruções de Execução — Protótipo Skipjack (IoT / WSN)

Este guia apresenta o passo a passo para executar a aplicação de proteção criptográfica telemétrica utilizando Python 3.12 e a cifra Skipjack, sem a necessidade de utilizar comandos de terminal.

1. Pré-requisitos

      Python 3.12 ou superior instalado no computador.
      
      Caso ainda não tenha o Python instalado, baixe o instalador oficial em python.org/downloads e execute-o normalmente. Durante a instalação no Windows, marque a opção "Add python.exe to PATH" antes de clicar em       Install Now.
      
      Nenhuma biblioteca externa é necessária: o protótipo utiliza apenas módulos nativos do Python (struct, secrets, time e os).

2. Como Executar (Escolha uma das opções abaixo)

    Opção A: Usando o IDLE (Já vem instalado com o Python) — Mais simples

        Abra a pasta onde estão salvos os arquivos do projeto.
        
        Clique com o botão direito sobre o arquivo app_iot.py.
        
        Selecione a opção Edit with IDLE (ou Abrir com > IDLE).
        
        Com o arquivo aberto na janela do IDLE, clique no menu superior Run e depois em Run Module (ou apenas pressione a tecla F5).
        
        Uma nova janela será aberta exibindo o menu interativo da aplicação.

    Opção B: Usando o Visual Studio Code (VS Code)

        Abra o VS Code.
        
        No menu superior, clique em Arquivo (File) > Abrir Pasta (Open Folder) e selecione a pasta do projeto.
        
        No painel lateral esquerdo (Explorador), clique sobre o arquivo app_iot.py para abri-lo.
        
        Clique no botão Executar (ícone de Play ▶️) localizado no canto superior direito da tela.
        
        O menu interativo aparecerá automaticamente na parte inferior da janela do VS Code.

3. Como Usar o Protótipo

      Ao iniciar o programa, você verá o menu principal com três opções:
      
          1) Validar a cifra com o vetor oficial do NIST (Recomendado primeiro)
          
              Digite 2 e pressione Enter.
              
              O sistema testará automaticamente a implementação com a chave e a entrada oficiais do NIST (1998) e exibirá [APROVADO] confirmando a fidelidade à especificação FIPS 185.

          2) Simular transmissão segura (Nó Sensor → Estação Base)
          
              Digite 1 e pressione Enter.
              
              Preencha os dados solicitados do sensor (ID, Temperatura, Umidade e uma mensagem/alerta opcional) — ou apenas pressione Enter para aceitar os valores padrão sugeridos entre colchetes.

      Escolha o modo de operação:
      
          1 para ECB (Electronic Codebook).
          
          2 para CBC (Cipher Block Chaining — recomendado).

      Defina a chave secreta de 80 bits:
      
          Digite S (ou pressione Enter) para gerar uma chave aleatória segura automaticamente.
          
          Digite n caso queira informar manualmente uma chave hexadecimal de 20 caracteres (exemplo: 00998877665544332211).

    Acompanhe na tela os dados cifrados trafegando no canal sem fio, o tempo de processamento e a confirmação de decifragem íntegra na Estação Receptora.

    3) Encerrar o programa

          No menu principal, digite 0 e pressione Enter.

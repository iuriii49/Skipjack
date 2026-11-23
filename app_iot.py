# Protótipo: Proteção Criptográfica em Redes de Sensores Sem Fio (IoT/WSN)
import os
import secrets
import time
import cripto


def obter_chave_80bits() -> bytes:
    print("\n--- Configuração da Chave Secreta (80 bits / 10 bytes) ---")
    opcao = input("Deseja gerar uma chave aleatória segura? (S/n): ").strip().lower()
    if opcao == 'n':
        while True:
            chave_hex = input("Informe a chave em hexadecimal (20 caracteres hex): ").strip()
            try:
                chave = bytes.fromhex(chave_hex)
                if len(chave) == 10:
                    return chave
                print("Erro: A chave deve ter exatamente 10 bytes (20 dígitos hexadecimais).")
            except ValueError:
                print("Erro: Formato hexadecimal inválido.")
    chave = secrets.token_bytes(10)
    print(f"Chave gerada (Hex): {chave.hex()}")
    return chave


def simular_transmissao():
    print("\n=== NÓ SENSOR (TRANSMISSOR IoT) ===")
    sensor_id = input("ID do Sensor [ex: SENS-01]: ").strip() or "SENS-01"
    temperatura = input("Temperatura (°C) [ex: 24.7]: ").strip() or "24.7"
    umidade = input("Umidade (%) [ex: 62.5]: ").strip() or "62.5"
    obs = input("Mensagem/Alerta adicional (opcional): ").strip()

    # Montagem do pacote telemétrico
    payload_str = f"ID={sensor_id}|TEMP={temperatura}C|UMID={umidade}%"
    if obs:
        payload_str += f"|MSG={obs}"
    payload_bytes = payload_str.encode("utf-8")

    # Escolha do modo operacional
    print("\nModo de Operação:")
    print("1 - ECB (Electronic Codebook)")
    print("2 - CBC (Cipher Block Chaining - recomendado)")
    modo = input("Escolha o modo (1 ou 2) [2]: ").strip() or "2"

    chave = obter_chave_80bits()

    # --- Cifragem no Nó Sensor ---
    t0 = time.perf_counter()
    if modo == "1":
        modo_nome = "ECB"
        iv = None
        ciphertext = cripto.encrypt_ecb(payload_bytes, chave)
    else:
        modo_nome = "CBC"
        iv, ciphertext = cripto.encrypt_cbc(payload_bytes, chave)
    t_cifra = (time.perf_counter() - t0) * 1000

    print("\n--- TRANSMISSÃO NO CANAL SEM FIO ---")
    print(f"Modo utilizado     : {modo_nome}")
    print(f"Payload original   : {payload_str} ({len(payload_bytes)} bytes)")
    if iv:
        print(f"Vetor IV (64 bits) : {iv.hex()}")
    print(f"Pacote Cifrado Hex : {ciphertext.hex()} ({len(ciphertext)} bytes)")
    print(f"Tempo de cifragem  : {t_cifra:.3f} ms")

    # --- Recepção e Decifragem na Estação Base ---
    print("\n=== ESTAÇÃO RECEPTORA (BASE WSN) ===")
    t1 = time.perf_counter()
    if modo == "1":
        recuperado_bytes = cripto.decrypt_ecb(ciphertext, chave)
    else:
        recuperado_bytes = cripto.decrypt_cbc(ciphertext, chave, iv)
    t_decifra = (time.perf_counter() - t1) * 1000

    recuperado_str = recuperado_bytes.decode("utf-8")
    print(f"Dados recuperados  : {recuperado_str}")
    print(f"Tempo de decifragem: {t_decifra:.3f} ms")

    if recuperado_bytes == payload_bytes:
        print("Status             : [OK] Telemetria decifrada com integridade total.")
    else:
        print("Status             : [ERRO] Falha na recuperação dos dados.")


def executar_teste_nist():
    print("\n=== VALIDAÇÃO OFICIAL (VETOR NIST 1998) ===")
    ok = cripto.validar_vetor_nist()
    print("Chave    : 00998877665544332211")
    print("Entrada  : 33221100ddccbbaa")
    print("Esperado : 2587cae27a12d300")
    print(f"Resultado: {'[APROVADO] Implementação fiel à especificação FIPS 185.' if ok else '[FALHA]'}")


def main():
    while True:
        print("\n" + "=" * 55)
        print("  PROJETO SKIPJACK — PROTEÇÃO TELEMÉTRICA IoT / WSN")
        print("=" * 55)
        print("1. Simular transmissão segura (Nó Sensor -> Estação Base)")
        print("2. Validar cifra com vetor oficial do NIST")
        print("0. Sair")
        escolha = input("Selecione uma opção: ").strip()

        if escolha == "1":
            simular_transmissao()
        elif escolha == "2":
            executar_teste_nist()
        elif escolha == "0":
            print("Encerrando protótipo...")
            break
        else:
            print("Opção inválida.")


if __name__ == "__main__":
    main()
import cripto


def teste_bit_flipping():
    print("\nTESTE DE CRIPTOANÁLISE: BIT-FLIPPING NO CBC")

    # Chave de teste (80 bits)
    chave = bytes.fromhex("00998877665544332211")

    # Mensagem original do sensor
    mensagem = b"TEMP=24C|ID=SENS-01"

    # Cifragem utilizando CBC
    iv, ciphertext = cripto.encrypt_cbc(mensagem, chave)

    print(f"\nMensagem original : {mensagem.decode()}")
    print(f"IV original       : {iv.hex()}")
    print(f"Ciphertext        : {ciphertext.hex()}")

    # Decifragem normal
    recuperado = cripto.decrypt_cbc(ciphertext, chave, iv)

    print(f"\nDecifragem normal : {recuperado.decode()}")
 

    # Queremos alterar o caractere '2' para '9'.
    # Posição 5 do primeiro bloco (TEMP=24C).
    diferenca = ord("2") ^ ord("9")

    # O atacante modifica o IV sem conhecer a chave.
    iv_adulterado = bytearray(iv)
    iv_adulterado[5] ^= diferenca

    # Decifragem utilizando o IV adulterado
    mensagem_adulterada = cripto.decrypt_cbc(
        ciphertext,
        chave,
        bytes(iv_adulterado)
    )

    print("\n--- RESULTADO DO ATAQUE ---")
    print(f"IV adulterado     : {bytes(iv_adulterado).hex()}")
    print(f"Mensagem recebida : {mensagem_adulterada.decode()}")

    if mensagem_adulterada == b"TEMP=94C|ID=SENS-01":
        print("\n[SUCESSO] Ataque Bit-Flipping demonstrado!")
        print("O atacante alterou a temperatura sem conhecer a chave.")
    else:
        print("\n[FALHA] O resultado não corresponde ao esperado.")


if __name__ == "__main__":
    teste_bit_flipping()
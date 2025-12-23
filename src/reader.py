import serial

# Połączenie
ser = serial.Serial('COM7', 115200)

while True:
    line = ser.readline().decode('ascii').strip()
    if line.startswith("FRAME:"):
        # Usuwamy prefiks i tniemy dane
        payload = line.replace("FRAME:", "")
        can_id, dlc, hex_data = payload.split("|")

        print(f"Odebrano ID: {can_id}, Dane: {hex_data}")
        # Tutaj dodasz swoją logikę wykrywania zmian (Delta)
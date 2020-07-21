import hashlib
import sys

target = "661ded81b6b99758643f19517a468331"

states = ["Alabama", "Alaska", "Arizona", "Arkansas", "California", "Colorado", "Connecticut", "Delaware", "Florida", "Georgia", "Hawaii", "Idaho", "Illinois", "Indiana", "Iowa", "Kansas", "Kentucky", "Louisiana", "Maine", "Maryland", "Massachusetts", "Michigan", "Minnesota", "Mississippi", "Missouri", "Montana", "Nebraska", "Nevada", "NewHampshire", "NewJersey", "NewMexico", "NewYork", "NorthCarolina", "NorthDakota", "Ohio", "Oklahoma", "Oregon", "Pennsylvania", "RhodeIsland", "SouthCarolina", "SouthDakota", "Tennessee", "Texas", "Utah", "Vermont", "Virginia", "Washington", "WestVirginia", "Wisconsin", "Wyoming"]
greek_gods = ["Aphrodite", "Apollo", "Ares", "Artemis", "Athena", "Demeter", "Dionysus", "Bacchus", "Hades", "Pluto", "Hephaestus", "Hera", "Hermes", "Hestia", "Poseidon", "Zeus"]

def hash(password):
    return hashlib.md5(password.encode()).hexdigest()

for god in greek_gods:
    for state in states:
        password = god + state
        if hash(password) == target:
            print(password)
            exit()
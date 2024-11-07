Erwan PIERRON
TD_Ransomware

1) L'algorithme de chiffrement est un XOR. la clef s'adapte à la longueur des données mais est très sensible à certaines attaques (analyse statistique: la fréquence d'apparition de chaque lettre permet de trouver son code).

2)Il ne faut pas hacher directement la clef car deux hachages de deux clefs différentes peuvent donner le même résultat. Cela serait possible avec le chiffrement hmac car il gère la possibilité de collision (deux mêmes chiffrements avec deuc clefs différentes).

3)Il est préférable de vérifier qu'un fichier token est déjà présent pour ne pas remplacer une cryptographie déjà réalisée

4) Pour vérifier si la clef est correcte, il faut dériver la clef fournie avec le même sel. Après, il suffit de comparer le résultat avec la clef de référence.

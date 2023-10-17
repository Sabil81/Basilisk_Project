import tkinter as tk
import requests
import scapy.all as scapy
import sys
import io
import socket
import time

root = tk.Tk()
root.title("Basilisk Toolkit ver0.2 ALPHA")
root.geometry("800x600")
root.configure(bg="#47494d")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8",80))
user_ip = s.getsockname()[0]
flag = 0

for i in range(0,len(user_ip)):
    if (user_ip[i]=="."):
        flag = flag + 1
    if (flag == 3):
        slice = user_ip[:i]
        allip = slice+".1/24"
        break

def pscan():
    old_stdout = sys.stdout
    sys.stdout = buffer = io.StringIO()
    out = scapy.arping(allip)
    sys.stdout = old_stdout
    whatWasPrinted = buffer.getvalue()
    outp1.delete("1.0",tk.END)
    outp1.insert(tk.END,whatWasPrinted,)
    buffer.close()
    outp1.update()

def livepscan():
    if (isinstance(int(ent1.get()),int) and int(ent1.get())>0):
        for i in range(1, int(ent1.get()) + 1):
            pscan()
            outp1.insert(tk.END, "\n")
            outp1.insert(tk.END, "Scan Count: " + str(i) + "\n")
            outp1.insert(tk.END, "Auto scanning in process.....PLEASE WAIT\n")
            outp1.update()
            time.sleep(2)
        outp1.insert(tk.END, "AUTO SCAN COMPLETE","b")
    else:
        outp1.delete("1.0",tk.END)
        outp1.insert(tk.END,"Invalid count number.Please enter a non-zero integer.")

main_txt = tk.Label(root, text="BASILISK v0.2", font=("Arial",25,"bold"), fg="#0CCA4A",bg="#47494d")
txt1 = tk.Label(root, text="NETWORK SCANNER:", font=("Arial", 12, "bold"), fg="#C8D3D5", bg="#47494d")
but1 = tk.Button(root, text="QUCIK SCAN", font=("Arial",10,"bold"), bg="#A4B8C4",command=pscan)
but2 = tk.Button(root, text="AUTO SCAN", font=("Arial",10,"bold"), bg="#A4B8C4",command=livepscan)
txt2 = tk.Label(root,text="ENTER SCAN COUNT:", font=("Arial",8,"bold"), bg="#47494d")
ent1 = tk.Entry(root,bg="#27292b",fg="#0CCA4A",font=("Arial",8,"bold"))
u_iptxt = tk.Label(root, text="YOUR LOCAL IP: "+s.getsockname()[0], font=("Arial",10,"bold"),bg="#47494d")
outtxt1 = tk.Label(root, text="DISCOVERED DEVICES:", font=("Arial",18,"bold"),bg="#47494d")
outp1 = tk.Text(root,font=("Arial",10,"bold"),bg="#27292b",fg="#0CCA4A" )
outp1.configure(height=15)

main_txt.pack(padx="8",pady="8")
txt1.pack()
but1.pack(pady=10)
but2.pack()
txt2.pack()
ent1.pack(pady=1)
u_iptxt.pack()
outtxt1.pack()
outp1.pack()
outp1.tag_config("b", foreground="#3d34eb")
outp1.tag_config("r", foreground="red")


root.mainloop()

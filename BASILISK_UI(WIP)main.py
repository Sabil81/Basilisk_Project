import customtkinter as ctk
import tkinter as tk
import scapy.all as scapy
import threading
import socket
import time
from PIL import Image,ImageTk
import getmac

#global Flags
networkscanmode = 1

#icons_LOAD
logo_icon = ctk.CTkImage(Image.open("D:/Basilisk_ui/venv/Basilisk_log.png"),size=(35,35))
networkscanbut = ctk.CTkImage(Image.open("D:/Basilisk_ui/venv/networkscannerbutton.png"),size=(35,35))
arpspoofbut = ctk.CTkImage(Image.open("D:/Basilisk_ui/venv/Arp_spoof_button.png"),size=(35,35))

#colors
grey = "#47494d"
dark_grey = "#27292b"
green = "#0CCA4A"
white = "#e6e6e6"
hovergreen = "#239e44"

#big text
linetxt1 = "Basilisk is a small,simple,does-what-it-says-software"
linetxt2 = "and is no way or in shape an industry standard software."
linetxt3 = "It is mainly a hobbyist project and is not intended to be"
linetxt4 = "used or integrated in a large scale enterprise enviroment."

root = ctk.CTk()
root.geometry("900x600")
root.title("Basilisk v2.0")
root.resizable(False,False)
root.configure(fg_color=dark_grey)
root.iconbitmap("D:/Basilisk_ui/venv/Basilisk_log.ico")


#functions
def copybutton():
    root.clipboard_clear()
    root.clipboard_append(basilisk_text6.cget("text"))

def de_highlight():
    menu1.configure(fg_color=grey)
    menu2.configure(fg_color=grey)
    menu3.configure(fg_color=grey)

def hidepages():
    entry_page.forget()
    networkscan_page.forget()
    spoof_page.forget()

def netscanpagebut():
    de_highlight()
    hidepages()
    networkscan_page.pack(padx=10,pady=10)
    networkscan_page.tkraise()
    menu2.configure(fg_color=green)

def titlepagebut():
    de_highlight()
    hidepages()
    entry_page.pack(padx=10,pady=10)
    entry_page.tkraise()
    menu1.configure(fg_color=green)

def spoofpagebut():
    de_highlight()
    hidepages()
    spoof_page.pack(padx=10,pady=10)
    spoof_page.tkraise()
    menu3.configure(fg_color=green)

def hostname(input):
    try:
        ret = socket.gethostbyaddr(input)[0]
        return ret
    except socket.herror:
        return "NOT FOUND"

def networkscanner():
    if networkscanmode == 1:
        scan_outputbox.insert(tk.END, "Scanning.... Response Timeout: "+str(timeout_label.cget("text")))
        tout = int(timeout_label.cget("text"))
        scan_outputbox.update()
        arp_request = scapy.ARP(pdst=allip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=tout, verbose=False)[0]

        scan_outputbox.delete("1.0", tk.END)
        scan_outputbox.insert(tk.END, "IP\t\tMAC Address\n--------------------------------------------------------")
        scan_outputbox.insert(tk.END, "\n")
        scan_outputbox.update()
        clients_list = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(client_dict)
            result = clients_list
        for client in result:
            scan_outputbox.insert(tk.END, client["ip"] + "\t\t" + client["mac"])
            scan_outputbox.insert(tk.END, "\n")
        scan_outputbox.update()

    if networkscanmode == 2:
        scan_outputbox.insert(tk.END, "Scanning.... Response Timeout: " + str(timeout_label.cget("text")))
        tout = int(timeout_label.cget("text"))
        scan_outputbox.update()
        arp_request = scapy.ARP(pdst=target_input.get(),hwdst="ff:ff:ff:ff:ff:ff")
        answered_list = scapy.sr1(arp_request, timeout=tout, verbose=False)
        if answered_list == "None":
            scan_outputbox.delete("1.0",ctk.END)
            scan_outputbox.insert(ctk.END,"No response from "+target_input.get())
        else:
            scan_outputbox.delete("1.0", ctk.END)
            scan_outputbox.insert(ctk.END, "[Response:] " + str(answered_list))


def networkscanner_thread():
    threading.Thread(target=networkscanner).start()

#socket section
my_ip = socket.gethostbyname(socket.gethostname())
my_mac = getmac.get_mac_address()
my_hostname = hostname(my_ip)

flag = 0
for i in range(0,len(my_ip)):
    if (my_ip[i]=="."):
        flag = flag + 1
    if (flag == 3):
        slice = my_ip[:i]
        allip = slice+".1/24"
        break

def timeout_silder(secs):
    timeout_label.configure(text=int((secs)))

def networkscanmode_switch(val):
    global networkscanmode
    if val == "Full-Scan":
        networkscanmode = 1
    if val == "Specific":
        networkscanmode = 2
    if networkscanmode == 1:
        target_input.configure(state="disabled")
    if networkscanmode == 2:
        target_input.configure(state="normal")

#menu frame
menu_frame = ctk.CTkFrame(master=root)
menu_frame.configure(height=600, width=50,fg_color=grey,bg_color=grey)
menu_frame.pack(side=ctk.LEFT)
menu_frame.pack_propagate(False)

#entry_page
entry_page = ctk.CTkFrame(master=root)
entry_page.configure(height=570,width=790, fg_color=grey)
entry_page.pack(pady=10, padx=10)
entry_page.pack_propagate(False)

basilisk_text = ctk.CTkLabel(master=entry_page, text="Basilisk.",font=("Arial",80,"bold"),text_color=green)
basilisk_text.pack(side=ctk.TOP,padx=20,pady=10,anchor=ctk.NW)

basilisk_text2 = ctk.CTkLabel(master=entry_page, text="[LAN Networking Tools Suite]", font=("Arial",30,"bold"),text_color=green)
basilisk_text2.pack(side=ctk.TOP,padx=20,anchor=ctk.NW)

basilisk_text3 = ctk.CTkLabel(master=entry_page, text="{Lightweight. Simple GUI. Easy To Use.}", font=("Arial",30,"bold"),text_color=white)
basilisk_text3.pack(side=ctk.TOP,padx=20,pady=10,anchor=ctk.NW)

basilisk_text4 = ctk.CTkLabel(master=entry_page, text="To enable packet forwarding on windows:", font=("Arial",20,"bold"),text_color=white)
basilisk_text4.pack(side=ctk.TOP,padx=20,pady=0,anchor=ctk.NW)

basilisk_text5 = ctk.CTkLabel(master=entry_page, text="[Run this in CMD]:", font=("Arial",15,"bold"),text_color=white)
basilisk_text5.pack(side=ctk.TOP,padx=20,anchor=ctk.NW)

entry_page_subframe1 = ctk.CTkFrame(master=entry_page)
entry_page_subframe1.configure(height=30,width=770,fg_color=dark_grey)
entry_page_subframe1.pack(side=ctk.TOP,anchor=ctk.NW, padx=20,pady=10)
entry_page_subframe1.pack_propagate(False)

basilisk_text6 = ctk.CTkLabel(master=entry_page_subframe1, text="reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /t REG_DWORD /v IPEnableRouter /d 1 /f", font=("Arial",11,"bold"),text_color=green)
basilisk_text6.pack(side=ctk.LEFT,padx=7)

copy_button = ctk.CTkButton(master=entry_page, text="Copy", font=("Arial",15,"bold"),fg_color=green,text_color=dark_grey,command=copybutton)
copy_button.configure(width=50)
copy_button.pack(side=ctk.TOP,anchor=ctk.NW,padx=20)

basilisk_text7 = ctk.CTkLabel(master=entry_page, text="[IMPORTANT:]", font=("Arial",20,"bold"),text_color=green)
basilisk_text7.pack(side=ctk.TOP,padx=20,pady=30,anchor=ctk.NW)

line1 = ctk.CTkLabel(master=entry_page, text=linetxt1, font=("Arial",20,"bold"),text_color=white)
line1.pack(side=ctk.TOP,padx=20,anchor=ctk.NW)

line2 = ctk.CTkLabel(master=entry_page, text=linetxt2, font=("Arial",20,"bold"),text_color=white)
line2.pack(side=ctk.TOP,padx=20,anchor=ctk.NW)

line3 = ctk.CTkLabel(master=entry_page, text=linetxt3, font=("Arial",20,"bold"),text_color=white)
line3.pack(side=ctk.TOP,padx=20,anchor=ctk.NW)

line4 = ctk.CTkLabel(master=entry_page, text=linetxt4, font=("Arial",20,"bold"),text_color=white)
line4.pack(side=ctk.TOP,padx=20,anchor=ctk.NW)

#NETWORK SCANNER PAGE!!!!!!
networkscan_page = ctk.CTkFrame(master=root)
networkscan_page.configure(height=570,width=790, fg_color=grey)
networkscan_page.pack_propagate(False)

networkscanner_title = ctk.CTkLabel(master=networkscan_page,text="Network Scanner", text_color=dark_grey,bg_color=green,font=("Arial",20,"bold"))
networkscanner_title.configure(width=790)
networkscanner_title.pack(side=ctk.TOP)

scansetting_frame = ctk.CTkFrame(networkscan_page)
scansetting_frame.configure(height=200,width=200,fg_color=dark_grey)
scansetting_frame.pack(side=ctk.TOP,anchor=ctk.NW,padx=30,pady=20)
scansetting_frame.pack_propagate(False)

your_details_title = ctk.CTkLabel(scansetting_frame,text="Your Device Details",text_color=dark_grey,font=("Arial",15,"bold"),bg_color=green)
your_details_title.configure(width=200)
your_details_title.pack()

my_ipdisplay = ctk.CTkLabel(master=scansetting_frame,text="IP: "+my_ip,text_color=green,font=("Arial",15,"bold"))
my_ipdisplay.pack(side=ctk.TOP,anchor=ctk.NW,padx=12,pady=5)

my_macdisplay = ctk.CTkLabel(master=scansetting_frame,text="MAC: "+my_mac,text_color=green,font=("Arial",15,"bold"))
my_macdisplay.pack(side=ctk.TOP,anchor=ctk.NW,padx=12,pady=5)

my_hostnamedisplay = ctk.CTkLabel(master=scansetting_frame,text=my_hostname,text_color=green,font=("Arial",15,"bold"))
my_hostnamedisplay.pack(side=ctk.TOP,anchor=ctk.NW,padx=12,pady=5)

scan_launchframe = ctk.CTkFrame(master=networkscan_page)
scan_launchframe.configure(height=300,width=200,fg_color=dark_grey)
scan_launchframe.pack(side=ctk.TOP,anchor=ctk.NW,padx=30,pady=15)
scan_launchframe.pack_propagate(False)

scan_launchframetitle = ctk.CTkLabel(master=scan_launchframe,text="Scan Settings",bg_color=green,text_color=dark_grey,font=("Arial",15,"bold"))
scan_launchframetitle.configure(width=200)
scan_launchframetitle.pack()

scan_launchbutton = ctk.CTkButton(master=scan_launchframe,text="Begin Scan",text_color=dark_grey, hover_color=hovergreen, font=("Arial",15,"bold"),fg_color=green,command=networkscanner_thread)
scan_launchbutton.pack(side=ctk.BOTTOM,pady=15)

timeout_label = ctk.CTkLabel(master=scan_launchframe,text="15",font=("Arial",15,"bold"),text_color=dark_grey,bg_color=green)
timeout_label.configure(width=35)
timeout_label.pack(side=ctk.BOTTOM)

timeout_slider = ctk.CTkSlider(master=scan_launchframe,from_=0,to=100,button_color=green, button_hover_color=hovergreen,progress_color=green,command=timeout_silder)
timeout_slider.configure(width=150)
timeout_slider.set(15)
timeout_slider.pack(side=ctk.BOTTOM,pady=5)

timeout_tittle = ctk.CTkLabel(master=scan_launchframe,text="Timeout [seconds]:",text_color=green,font=("Arial",15,"bold"))
timeout_tittle.pack(side=ctk.BOTTOM)

scanmode_button = ctk.CTkSegmentedButton(master=scan_launchframe,
                                         values=["Full-Scan","Specific"],
                                         text_color=dark_grey,
                                         selected_color=green,
                                         unselected_color=hovergreen,
                                         selected_hover_color=green,
                                         unselected_hover_color=green,
                                         fg_color=green,
                                         bg_color=dark_grey,
                                         font=("Arial",15,"bold"),command=networkscanmode_switch)
scanmode_button.set("Full-Scan")
scanmode_button.pack(pady=10)

target_input = ctk.CTkEntry(master=scan_launchframe,
                            fg_color=grey,
                            text_color=green,
                            font=("Arial",15,"bold"),
                            placeholder_text_color=dark_grey,
                            placeholder_text="Example:127.0.0.1",
                            border_color=grey,
                            width=160)
target_input.pack()


scan_outputframe = ctk.CTkFrame(master=networkscan_page)
scan_outputframe.configure(fg_color=dark_grey,height=509,width=510)
scan_outputframe.place(x=250,y=46.69)
scan_outputframe.pack_propagate(False)

scan_outputtitle = ctk.CTkLabel(master=scan_outputframe,text="Discovered Devices",text_color=dark_grey,fg_color=green,font=("Arial",15,"bold"))
scan_outputtitle.configure(width=510)
scan_outputtitle.pack()

scan_outputbox = ctk.CTkTextbox(master=scan_outputframe,fg_color=dark_grey,text_color=green,font=("Arial",15,"bold"))
scan_outputbox.configure(height=480,width=480)
scan_outputbox.pack()

#ARP SPOOF PAGE!!!!!!!!!!!!!!!!!!!!!!!!!

spoof_page = ctk.CTkFrame(master=root)
spoof_page.configure(height=570,width=790, fg_color=grey)
spoof_page.pack_propagate(False)

spoofpage_title = ctk.CTkLabel(master=spoof_page,text="ARP Spoofing", text_color=dark_grey,bg_color=green,font=("Arial",20,"bold"))
spoofpage_title.configure(width=790)
spoofpage_title.pack(side=ctk.TOP)

#menu_frame_buttons
menu1 = ctk.CTkButton(master=menu_frame, text="", image=logo_icon, fg_color=grey,hover_color=green,command=titlepagebut)
menu1.configure(height=10,width=10)
menu1.pack(pady=3)

menu2 = ctk.CTkButton(master=menu_frame, text="",image=networkscanbut, fg_color=grey,hover_color=green,command=netscanpagebut)
menu2.configure(height=10,width=10)
menu2.pack(pady=3)

menu3 = ctk.CTkButton(master=menu_frame, text="",image=arpspoofbut, fg_color=grey,hover_color=green,command=spoofpagebut)
menu3.configure(height=10,width=10)
menu3.pack(pady=3)



root.mainloop()

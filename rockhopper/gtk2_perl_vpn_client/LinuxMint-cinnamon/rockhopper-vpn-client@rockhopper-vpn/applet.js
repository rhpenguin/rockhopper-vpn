const Lang = imports.lang;
const Applet = imports.ui.applet;
const GLib = imports.gi.GLib;

function MyApplet(orientation, panel_height) {
    this._init(orientation, panel_height);
}

MyApplet.prototype = {
    __proto__: Applet.IconApplet.prototype,

    _init: function(orientation, panel_height) {        

        Applet.IconApplet.prototype._init.call(this, orientation, panel_height);
        
        try {        
            this.set_applet_icon_symbolic_name("network-vpn-symbolic");
            this.set_applet_tooltip(_("Rockhopper VPN Client"));
        }
        catch (e) {
            global.logError(e);
        }
    },
    
    on_applet_clicked: function(event) {
        GLib.spawn_command_line_async('/usr/local/sbin/rhp_client.pl');
    }
};


function main(metadata, orientation, panel_height) {      
    let myApplet = new MyApplet(orientation, panel_height);
    return myApplet;      
}

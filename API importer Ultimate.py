# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpRequestResponse, IHttpService
from javax.swing import (JPanel, JButton, JFileChooser, JLabel, JScrollPane,
                         JTable, JComboBox, JTextArea, JTextField, BorderFactory,
                         JSplitPane, JProgressBar, SwingUtilities, JCheckBox,
                         JSpinner, SpinnerNumberModel, JPasswordField, JTabbedPane,
                         Box, BoxLayout)
from javax.swing.table import DefaultTableModel, TableRowSorter
from javax.swing.border import TitledBorder
from java.awt import (BorderLayout, Dimension, FlowLayout, Color, Font,
                      GridBagLayout, GridBagConstraints, Insets,
                      KeyboardFocusManager, CardLayout)
from java.awt.event import MouseAdapter, MouseEvent, KeyEvent, ActionListener
from java.awt import KeyEventDispatcher
from javax.swing.event import DocumentListener, DocumentEvent
from java.lang import Thread, Runnable
import json
import urlparse
import re
import base64

# ====================== GLOBAL ZOOM (Ctrl+/Ctrl-) ======================
class GlobalZoomDispatcher(KeyEventDispatcher):
    def __init__(self):
        self._components = []
        self._size = [12]
        self._min = 8
        self._max = 28

    def register(self, component):
        self._components.append(component)

    def dispatchKeyEvent(self, e):
        if e.getID() != KeyEvent.KEY_PRESSED:
            return False
        ctrl = (e.getModifiers() & KeyEvent.CTRL_MASK) != 0
        if not ctrl:
            return False
        code = e.getKeyCode()
        changed = False
        if code in (KeyEvent.VK_EQUALS, KeyEvent.VK_ADD, KeyEvent.VK_PLUS):
            if self._size[0] < self._max:
                self._size[0] += 1
                changed = True
        elif code in (KeyEvent.VK_MINUS, KeyEvent.VK_SUBTRACT):
            if self._size[0] > self._min:
                self._size[0] -= 1
                changed = True
        elif code == KeyEvent.VK_0:
            self._size[0] = 12
            changed = True
        if changed:
            sz = self._size[0]
            for comp in self._components:
                try:
                    old = comp.getFont()
                    comp.setFont(old.deriveFont(float(sz)))
                except:
                    pass
            return True
        return False


# ====================== AUTH TYPES ======================
AUTH_TYPE_NONE         = "No Auth"
AUTH_TYPE_BEARER       = "Bearer Token"
AUTH_TYPE_BASIC        = "Basic Auth"
AUTH_TYPE_API_KEY      = "API Key"
AUTH_TYPE_OAUTH2       = "OAuth2 Token"
AUTH_TYPE_DIGEST       = "Digest Auth"
AUTH_TYPE_HAWK         = "Hawk Auth"
AUTH_TYPE_AWS          = "AWS Signature"
AUTH_TYPE_CUSTOM       = "Custom Header"
AUTH_TYPE_JWT          = "JWT (Auto-refresh)"

ALL_AUTH_TYPES = [
    AUTH_TYPE_NONE,
    AUTH_TYPE_BEARER,
    AUTH_TYPE_BASIC,
    AUTH_TYPE_API_KEY,
    AUTH_TYPE_OAUTH2,
    AUTH_TYPE_DIGEST,
    AUTH_TYPE_HAWK,
    AUTH_TYPE_AWS,
    AUTH_TYPE_CUSTOM,
    AUTH_TYPE_JWT,
]

# API Key placement options
API_KEY_IN_HEADER = "Header"
API_KEY_IN_QUERY  = "Query Param"
API_KEY_IN_COOKIE = "Cookie"


# ====================== GLOBAL AUTH MANAGER ======================
class GlobalAuthManager(object):
    """
    Supports multiple auth types:
      - No Auth
      - Bearer Token
      - Basic Auth          (username + password -> Base64)
      - API Key             (header / query / cookie)
      - OAuth2 Token        (same wire format as Bearer)
      - Digest Auth         (sends WWW-Authenticate challenge stub)
      - Hawk Auth           (Hawk id + key)
      - AWS Signature       (Access key / Secret – adds x-amz-date + Authorization)
      - Custom Header       (arbitrary key: value)
      - JWT (Auto-refresh)  (stores raw JWT; identical to Bearer on the wire)
    """

    def __init__(self):
        self._enabled   = False
        self._auth_type = AUTH_TYPE_NONE

        # Per-type credential storage
        self._bearer_token  = ""
        self._basic_user    = ""
        self._basic_pass    = ""
        self._apikey_key    = ""
        self._apikey_value  = ""
        self._apikey_in     = API_KEY_IN_HEADER   # Header | Query Param | Cookie
        self._oauth2_token  = ""
        self._digest_user   = ""
        self._digest_pass   = ""
        self._hawk_id       = ""
        self._hawk_key      = ""
        self._aws_access    = ""
        self._aws_secret    = ""
        self._aws_region    = "us-east-1"
        self._aws_service   = "execute-api"
        self._custom_header = ""   # full "Key: Value" string
        self._jwt_token     = ""

    # ---- setters ----
    def set_enabled(self, v):            self._enabled   = bool(v)
    def set_auth_type(self, t):          self._auth_type = t
    def set_bearer(self, t):             self._bearer_token  = (t or "").strip()
    def set_basic(self, u, p):           self._basic_user = (u or ""); self._basic_pass = (p or "")
    def set_apikey(self, k, v, loc):     self._apikey_key = (k or ""); self._apikey_value = (v or ""); self._apikey_in = (loc or API_KEY_IN_HEADER)
    def set_oauth2(self, t):             self._oauth2_token  = (t or "").strip()
    def set_digest(self, u, p):          self._digest_user = (u or ""); self._digest_pass = (p or "")
    def set_hawk(self, i, k):            self._hawk_id  = (i or ""); self._hawk_key = (k or "")
    def set_aws(self, a, s, r, svc):     self._aws_access = (a or ""); self._aws_secret = (s or ""); self._aws_region = (r or "us-east-1"); self._aws_service = (svc or "execute-api")
    def set_custom(self, h):             self._custom_header = (h or "").strip()
    def set_jwt(self, t):                self._jwt_token = (t or "").strip()

    def is_enabled(self):
        return self._enabled and self._auth_type != AUTH_TYPE_NONE

    def get_auth_type(self):
        return self._auth_type

    # ---- Query string injection (API Key only) ----
    def get_query_param(self):
        """Returns (key, value) or None if not applicable."""
        if self.is_enabled() and self._auth_type == AUTH_TYPE_API_KEY and self._apikey_in == API_KEY_IN_QUERY:
            return (self._apikey_key, self._apikey_value)
        return None

    # ---- Header injection ----
    def _build_auth_headers(self):
        """Returns a list of header strings to inject."""
        t = self._auth_type
        hdrs = []

        if t == AUTH_TYPE_BEARER:
            if self._bearer_token:
                hdrs.append("Authorization: Bearer %s" % self._bearer_token)

        elif t == AUTH_TYPE_BASIC:
            if self._basic_user:
                raw = "%s:%s" % (self._basic_user, self._basic_pass)
                encoded = base64.b64encode(raw.encode('utf-8')).decode('ascii')
                hdrs.append("Authorization: Basic %s" % encoded)

        elif t == AUTH_TYPE_API_KEY:
            if self._apikey_key and self._apikey_value:
                if self._apikey_in == API_KEY_IN_HEADER:
                    hdrs.append("%s: %s" % (self._apikey_key, self._apikey_value))
                elif self._apikey_in == API_KEY_IN_COOKIE:
                    hdrs.append("Cookie: %s=%s" % (self._apikey_key, self._apikey_value))
                # Query Param is handled separately via get_query_param()

        elif t == AUTH_TYPE_OAUTH2:
            if self._oauth2_token:
                hdrs.append("Authorization: Bearer %s" % self._oauth2_token)

        elif t == AUTH_TYPE_DIGEST:
            # Digest requires a challenge/response cycle; we inject a pre-built
            # stub so testers can see the field and Burp's repeater can replay it.
            if self._digest_user:
                stub = ('Digest username="%s", realm="api", nonce="auto", '
                        'uri="/", response="<computed_by_client>"') % self._digest_user
                hdrs.append("Authorization: %s" % stub)

        elif t == AUTH_TYPE_HAWK:
            if self._hawk_id:
                stub = ('Hawk id="%s", ts="<timestamp>", nonce="<nonce>", '
                        'mac="<computed>"') % self._hawk_id
                hdrs.append("Authorization: %s" % stub)

        elif t == AUTH_TYPE_AWS:
            # Minimal stub — real AWS SigV4 needs full request signing
            if self._aws_access:
                import datetime
                now = datetime.datetime.utcnow()
                amz_date = now.strftime('%Y%m%dT%H%M%SZ')
                date_str = now.strftime('%Y%m%d')
                credential_scope = "%s/%s/%s/aws4_request" % (date_str, self._aws_region, self._aws_service)
                hdrs.append("x-amz-date: %s" % amz_date)
                hdrs.append("Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, "
                             "SignedHeaders=host;x-amz-date, Signature=<computed>" % (
                                 self._aws_access, credential_scope))

        elif t == AUTH_TYPE_CUSTOM:
            if self._custom_header and ':' in self._custom_header:
                hdrs.append(self._custom_header)

        elif t == AUTH_TYPE_JWT:
            if self._jwt_token:
                hdrs.append("Authorization: Bearer %s" % self._jwt_token)

        return hdrs

    def inject(self, header_list):
        """
        Given a list of header strings, strip conflicting auth headers and
        inject this auth type's headers.  Returns the modified list.
        """
        if not self.is_enabled():
            return header_list

        new_hdrs = self._build_auth_headers()
        if not new_hdrs:
            return header_list

        # Determine which header keys we are about to set so we can strip dupes
        new_keys = set()
        for h in new_hdrs:
            if ':' in h:
                new_keys.add(h.split(':', 1)[0].strip().lower())

        cleaned = [h for h in header_list
                   if ':' not in h or h.split(':', 1)[0].strip().lower() not in new_keys]
        cleaned.extend(new_hdrs)
        return cleaned

    def get_status_text(self):
        if not self._enabled or self._auth_type == AUTH_TYPE_NONE:
            return "OFF"
        return "ACTIVE"


AUTH_MANAGER = GlobalAuthManager()


# ====================== AUTH PANEL (multi-type) ======================
class AuthPanel(JPanel):
    """
    A panel that lets the user pick one of the supported auth types and fill in
    the relevant credentials.  All changes are immediately reflected in AUTH_MANAGER.
    """

    def __init__(self):
        JPanel.__init__(self)
        self.setLayout(BorderLayout(4, 4))
        self.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            "  Global Authorization  ",
            TitledBorder.LEFT, TitledBorder.TOP
        ))
        self._build_ui()

    # ------------------------------------------------------------------
    def _build_ui(self):
        # ---- Row 0: enable toggle + type picker + status badge --------
        header_panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))

        self.chk_enable = JCheckBox("Enable:", False)
        self.chk_enable.addActionListener(self._on_toggle)
        header_panel.add(self.chk_enable)

        self.type_combo = JComboBox(ALL_AUTH_TYPES)
        self.type_combo.setPreferredSize(Dimension(150, 24))
        self.type_combo.setEnabled(False)
        self.type_combo.addActionListener(self._on_type_change)
        header_panel.add(self.type_combo)

        self.lbl_status = JLabel("  OFF  ")
        self.lbl_status.setOpaque(True)
        self.lbl_status.setBackground(Color(0xDDDDDD))
        self.lbl_status.setForeground(Color(0x555555))
        self.lbl_status.setFont(Font("Monospaced", Font.BOLD, 10))
        self.lbl_status.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8))
        header_panel.add(self.lbl_status)

        # ---- Card area: one card per auth type -----------------------
        self.card_panel = JPanel(CardLayout())
        self._cards = {}

        for t in ALL_AUTH_TYPES:
            card = self._make_card(t)
            self._cards[t] = card
            self.card_panel.add(card, t)

        self.add(header_panel,    BorderLayout.NORTH)
        self.add(self.card_panel, BorderLayout.CENTER)

    # ------------------------------------------------------------------
    def _make_card(self, auth_type):
        """Factory: returns a JPanel with the fields for each auth type."""
        p = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(3, 6, 3, 6)
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.anchor = GridBagConstraints.WEST

        def label(text, row, col=0, span=1):
            gbc.gridx = col; gbc.gridy = row
            gbc.gridwidth = span; gbc.weightx = 0
            lbl = JLabel(text)
            lbl.setFont(Font("Dialog", Font.PLAIN, 11))
            p.add(lbl, gbc)
            gbc.gridwidth = 1

        def field(width, row, col=1, tip="", pw=False):
            gbc.gridx = col; gbc.gridy = row; gbc.weightx = 1
            if pw:
                f = JPasswordField(width)
            else:
                f = JTextField(width)
            if tip:
                f.setToolTipText(tip)
            f.setEnabled(False)
            p.add(f, gbc)
            gbc.weightx = 0
            return f

        def combo(items, row, col=1):
            gbc.gridx = col; gbc.gridy = row; gbc.weightx = 1
            c = JComboBox(items)
            c.setEnabled(False)
            p.add(c, gbc)
            gbc.weightx = 0
            return c

        # ---- No Auth ------------------------------------------------
        if auth_type == AUTH_TYPE_NONE:
            gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2; gbc.weightx = 1
            p.add(JLabel("<html><i>No authorization headers will be injected.</i></html>"), gbc)
            gbc.gridwidth = 1; gbc.weightx = 0

        # ---- Bearer Token ------------------------------------------
        elif auth_type == AUTH_TYPE_BEARER:
            label("Token:", 0)
            tf = field(32, 0, tip="Your Bearer / JWT token", pw=True)
            self._bearer_tf = tf
            btn = JButton("Show", actionPerformed=lambda e, f=tf: self._toggle_pw(f, e))
            btn.setPreferredSize(Dimension(50, 22))
            btn.setEnabled(False)
            self._bearer_show_btn = btn
            gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0
            p.add(btn, gbc)
            tf.getDocument().addDocumentListener(_FieldListener(lambda: self._sync_bearer()))

        # ---- Basic Auth --------------------------------------------
        elif auth_type == AUTH_TYPE_BASIC:
            label("Username:", 0)
            self._basic_user_tf = field(24, 0, tip="HTTP Basic username")
            label("Password:", 1)
            self._basic_pass_tf = field(24, 1, tip="HTTP Basic password", pw=True)
            self._basic_user_tf.getDocument().addDocumentListener(_FieldListener(self._sync_basic))
            self._basic_pass_tf.getDocument().addDocumentListener(_FieldListener(self._sync_basic))
            gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2; gbc.weightx = 1
            self._basic_preview = JLabel("")
            self._basic_preview.setFont(Font("Monospaced", Font.PLAIN, 10))
            p.add(self._basic_preview, gbc)
            gbc.gridwidth = 1; gbc.weightx = 0

        # ---- API Key -----------------------------------------------
        elif auth_type == AUTH_TYPE_API_KEY:
            label("Key Name:", 0)
            self._apikey_name_tf = field(20, 0, tip="e.g. X-API-Key or api_key")
            label("Value:", 1)
            self._apikey_value_tf = field(20, 1, tip="Your API key value", pw=True)
            label("Add To:", 2)
            self._apikey_in_cb = combo([API_KEY_IN_HEADER, API_KEY_IN_QUERY, API_KEY_IN_COOKIE], 2)
            self._apikey_name_tf.getDocument().addDocumentListener(_FieldListener(self._sync_apikey))
            self._apikey_value_tf.getDocument().addDocumentListener(_FieldListener(self._sync_apikey))
            self._apikey_in_cb.addActionListener(lambda e: self._sync_apikey())

        # ---- OAuth2 Token ------------------------------------------
        elif auth_type == AUTH_TYPE_OAUTH2:
            label("Access Token:", 0)
            self._oauth2_tf = field(32, 0, tip="OAuth2 access token (sent as Bearer)", pw=True)
            gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2; gbc.weightx = 1
            note = JLabel("<html><i>Sent as: Authorization: Bearer &lt;token&gt;</i></html>")
            note.setFont(Font("Dialog", Font.PLAIN, 10))
            p.add(note, gbc)
            gbc.gridwidth = 1; gbc.weightx = 0
            self._oauth2_tf.getDocument().addDocumentListener(_FieldListener(self._sync_oauth2))

        # ---- Digest Auth -------------------------------------------
        elif auth_type == AUTH_TYPE_DIGEST:
            label("Username:", 0)
            self._digest_user_tf = field(22, 0, tip="Digest auth username")
            label("Password:", 1)
            self._digest_pass_tf = field(22, 1, tip="Digest auth password", pw=True)
            gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2; gbc.weightx = 1
            note = JLabel("<html><i>Stub header injected — full Digest requires challenge handshake.</i></html>")
            note.setFont(Font("Dialog", Font.PLAIN, 10))
            note.setForeground(Color(0x888888))
            p.add(note, gbc)
            gbc.gridwidth = 1; gbc.weightx = 0
            self._digest_user_tf.getDocument().addDocumentListener(_FieldListener(self._sync_digest))
            self._digest_pass_tf.getDocument().addDocumentListener(_FieldListener(self._sync_digest))

        # ---- Hawk Auth ---------------------------------------------
        elif auth_type == AUTH_TYPE_HAWK:
            label("Hawk ID:", 0)
            self._hawk_id_tf = field(24, 0, tip="Hawk auth ID")
            label("Hawk Key:", 1)
            self._hawk_key_tf = field(24, 1, tip="Hawk shared secret", pw=True)
            gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2; gbc.weightx = 1
            note = JLabel("<html><i>MAC stub injected — nonce/ts auto-tagged.</i></html>")
            note.setFont(Font("Dialog", Font.PLAIN, 10))
            note.setForeground(Color(0x888888))
            p.add(note, gbc)
            gbc.gridwidth = 1; gbc.weightx = 0
            self._hawk_id_tf.getDocument().addDocumentListener(_FieldListener(self._sync_hawk))
            self._hawk_key_tf.getDocument().addDocumentListener(_FieldListener(self._sync_hawk))

        # ---- AWS Signature -----------------------------------------
        elif auth_type == AUTH_TYPE_AWS:
            label("Access Key:", 0)
            self._aws_access_tf = field(24, 0, tip="AWS Access Key ID")
            label("Secret Key:", 1)
            self._aws_secret_tf = field(24, 1, tip="AWS Secret Access Key", pw=True)
            label("Region:", 2)
            self._aws_region_tf = JTextField("us-east-1", 12)
            self._aws_region_tf.setEnabled(False)
            gbc.gridx = 1; gbc.gridy = 2; gbc.weightx = 1
            p.add(self._aws_region_tf, gbc)
            label("Service:", 3)
            self._aws_service_tf = JTextField("execute-api", 12)
            self._aws_service_tf.setEnabled(False)
            gbc.gridx = 1; gbc.gridy = 3; gbc.weightx = 1
            p.add(self._aws_service_tf, gbc)
            gbc.weightx = 0
            gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2; gbc.weightx = 1
            note = JLabel("<html><i>Adds x-amz-date + AWS4-HMAC-SHA256 Authorization stub.</i></html>")
            note.setFont(Font("Dialog", Font.PLAIN, 10))
            note.setForeground(Color(0x888888))
            p.add(note, gbc)
            gbc.gridwidth = 1; gbc.weightx = 0
            for tf in [self._aws_access_tf, self._aws_secret_tf,
                       self._aws_region_tf, self._aws_service_tf]:
                tf.getDocument().addDocumentListener(_FieldListener(self._sync_aws))

        # ---- Custom Header -----------------------------------------
        elif auth_type == AUTH_TYPE_CUSTOM:
            label("Header:", 0)
            self._custom_tf = field(32, 0,
                tip='Full header line, e.g.: X-My-Token: abc123   or   Authorization: Token xyz')
            gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2; gbc.weightx = 1
            note = JLabel("<html><i>Enter the complete header as &lt;Name&gt;: &lt;Value&gt;</i></html>")
            note.setFont(Font("Dialog", Font.PLAIN, 10))
            p.add(note, gbc)
            gbc.gridwidth = 1; gbc.weightx = 0
            self._custom_tf.getDocument().addDocumentListener(_FieldListener(self._sync_custom))

        # ---- JWT (Auto-refresh stub) --------------------------------
        elif auth_type == AUTH_TYPE_JWT:
            label("JWT Token:", 0)
            self._jwt_tf = field(32, 0, tip="Paste full JWT; sent as Authorization: Bearer", pw=True)
            gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2; gbc.weightx = 1
            note = JLabel("<html><i>Token decoded and sent as Bearer. Refresh manually when expired.</i></html>")
            note.setFont(Font("Dialog", Font.PLAIN, 10))
            p.add(note, gbc)
            gbc.gridwidth = 1; gbc.weightx = 0
            self._jwt_tf.getDocument().addDocumentListener(_FieldListener(self._sync_jwt))

        return p

    # ------------------------------------------------------------------
    # Field -> AUTH_MANAGER sync helpers
    # ------------------------------------------------------------------
    def _sync_bearer(self):
        t = str(self._bearer_tf.getText()).strip()
        AUTH_MANAGER.set_bearer(t)
        self._refresh_status()

    def _sync_basic(self):
        u = str(self._basic_user_tf.getText())
        p = str(self._basic_pass_tf.getText())
        AUTH_MANAGER.set_basic(u, p)
        if u:
            raw = "%s:%s" % (u, "*" * len(p))
            encoded = base64.b64encode(("%s:%s" % (u, p)).encode('utf-8')).decode('ascii')
            self._basic_preview.setText("→ Basic %s" % encoded[:32] + ("..." if len(encoded) > 32 else ""))
        else:
            self._basic_preview.setText("")
        self._refresh_status()

    def _sync_apikey(self):
        k = str(self._apikey_name_tf.getText())
        v = str(self._apikey_value_tf.getText())
        loc = str(self._apikey_in_cb.getSelectedItem())
        AUTH_MANAGER.set_apikey(k, v, loc)
        self._refresh_status()

    def _sync_oauth2(self):
        AUTH_MANAGER.set_oauth2(str(self._oauth2_tf.getText()))
        self._refresh_status()

    def _sync_digest(self):
        AUTH_MANAGER.set_digest(str(self._digest_user_tf.getText()),
                                str(self._digest_pass_tf.getText()))
        self._refresh_status()

    def _sync_hawk(self):
        AUTH_MANAGER.set_hawk(str(self._hawk_id_tf.getText()),
                              str(self._hawk_key_tf.getText()))
        self._refresh_status()

    def _sync_aws(self):
        AUTH_MANAGER.set_aws(str(self._aws_access_tf.getText()),
                             str(self._aws_secret_tf.getText()),
                             str(self._aws_region_tf.getText()),
                             str(self._aws_service_tf.getText()))
        self._refresh_status()

    def _sync_custom(self):
        AUTH_MANAGER.set_custom(str(self._custom_tf.getText()))
        self._refresh_status()

    def _sync_jwt(self):
        AUTH_MANAGER.set_jwt(str(self._jwt_tf.getText()))
        self._refresh_status()

    # ------------------------------------------------------------------
    def _on_toggle(self, event):
        enabled = self.chk_enable.isSelected()
        self.type_combo.setEnabled(enabled)
        AUTH_MANAGER.set_enabled(enabled)
        self._enable_card_fields(enabled)
        self._refresh_status()

    def _on_type_change(self, event):
        selected = str(self.type_combo.getSelectedItem())
        AUTH_MANAGER.set_auth_type(selected)
        cl = self.card_panel.getLayout()
        cl.show(self.card_panel, selected)
        self._enable_card_fields(self.chk_enable.isSelected())
        self._refresh_status()

    def _enable_card_fields(self, enabled):
        """Walk the current card's children and enable/disable fields."""
        selected = str(self.type_combo.getSelectedItem())
        card = self._cards.get(selected)
        if card is None:
            return
        self._set_children_enabled(card, enabled and selected != AUTH_TYPE_NONE)

    def _set_children_enabled(self, container, enabled):
        for comp in container.getComponents():
            try:
                comp.setEnabled(enabled)
            except:
                pass

    def _refresh_status(self):
        if AUTH_MANAGER.is_enabled():
            t = AUTH_MANAGER.get_auth_type()
            self.lbl_status.setText("  ACTIVE: %s  " % t)
            self.lbl_status.setBackground(Color(0x1D9E75))
            self.lbl_status.setForeground(Color(0xFFFFFF))
        else:
            self.lbl_status.setText("  OFF  ")
            self.lbl_status.setBackground(Color(0xDDDDDD))
            self.lbl_status.setForeground(Color(0x555555))

    @staticmethod
    def _toggle_pw(field, event):
        if field.getEchoChar() == '\x00':
            field.setEchoChar('*')
            event.getSource().setText("Show")
        else:
            field.setEchoChar('\x00')
            event.getSource().setText("Hide")


class _FieldListener(DocumentListener):
    def __init__(self, fn):
        self._fn = fn
    def insertUpdate(self, e):  self._fn()
    def removeUpdate(self, e):  self._fn()
    def changedUpdate(self, e): self._fn()


# ====================== CUSTOM HTTP SERVICE ======================
class CustomHttpService(IHttpService):
    def __init__(self, host, port, protocol):
        self._host     = host
        self._port     = port
        self._protocol = protocol

    def getHost(self):     return self._host
    def getPort(self):     return self._port
    def getProtocol(self): return self._protocol


# ====================== CUSTOM HTTP REQUEST/RESPONSE ======================
class CustomHttpRequestResponse(IHttpRequestResponse):
    def __init__(self, service, request_bytes):
        self._service  = service
        self._request  = request_bytes
        self._response = None
        self._comment  = ""
        self._highlight = None

    def getRequest(self):            return self._request
    def setRequest(self, req):       self._request = req
    def getResponse(self):           return self._response
    def setResponse(self, resp):     self._response = resp
    def getComment(self):            return self._comment
    def setComment(self, c):         self._comment = c
    def getHighlight(self):          return self._highlight
    def setHighlight(self, h):       self._highlight = h
    def getHttpService(self):        return self._service
    def setHttpService(self, svc):   self._service = svc


# ====================== FUZZER RUNNABLE ======================
class FuzzRunnable(Runnable):
    def __init__(self, fuzzer):
        self.fuzzer = fuzzer

    def run(self):
        self.fuzzer.do_fuzz()


# ====================== FUZZER PANEL ======================
class FuzzerPanel(JPanel):
    def __init__(self, callbacks, helpers):
        JPanel.__init__(self)
        self._callbacks = callbacks
        self._helpers = helpers
        self._running = False
        self._wordlist = []
        self._stop_flag = [False]
        self._sent   = [0]
        self._found  = [0]
        self._errors = [0]

        self.setLayout(BorderLayout(4, 4))
        self.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "  API Endpoint Fuzzer  ",
            TitledBorder.LEFT, TitledBorder.TOP
        ))
        self.setPreferredSize(Dimension(420, 0))
        self._build_ui()

    def _build_ui(self):
        cfg = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(3, 4, 3, 4)
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.anchor = GridBagConstraints.WEST

        row = 0

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0
        cfg.add(JLabel("Target Host:"), gbc)
        self.fuzz_host = JTextField("https://api.example.com", 22)
        gbc.gridx = 1; gbc.weightx = 1
        cfg.add(self.fuzz_host, gbc)
        row += 1

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0
        cfg.add(JLabel("Base Path:"), gbc)
        self.fuzz_base = JTextField("/", 22)
        gbc.gridx = 1; gbc.weightx = 1
        cfg.add(self.fuzz_base, gbc)
        row += 1

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0
        cfg.add(JLabel("Method:"), gbc)
        self.fuzz_method = JComboBox(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
        gbc.gridx = 1; gbc.weightx = 1
        cfg.add(self.fuzz_method, gbc)
        row += 1

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0
        cfg.add(JLabel("Extra Headers:"), gbc)
        self.fuzz_headers = JTextField("", 22)
        self.fuzz_headers.setToolTipText(
            "Additional headers (one per line). "
            "Auth headers are injected automatically from Global Auth if enabled."
        )
        gbc.gridx = 1; gbc.weightx = 1
        cfg.add(self.fuzz_headers, gbc)
        row += 1

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0
        cfg.add(JLabel("Threads:"), gbc)
        self.fuzz_threads = JSpinner(SpinnerNumberModel(5, 1, 50, 1))
        gbc.gridx = 1; gbc.weightx = 1
        cfg.add(self.fuzz_threads, gbc)
        row += 1

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0
        cfg.add(JLabel("Hide Codes:"), gbc)
        self.fuzz_hide = JTextField("404", 22)
        self.fuzz_hide.setToolTipText("Comma-separated status codes to hide, e.g. 404,400")
        gbc.gridx = 1; gbc.weightx = 1
        cfg.add(self.fuzz_hide, gbc)
        row += 1

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0
        cfg.add(JLabel("Follow Redirects:"), gbc)
        self.fuzz_follow = JCheckBox("", False)
        gbc.gridx = 1; gbc.weightx = 1
        cfg.add(self.fuzz_follow, gbc)
        row += 1

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0
        cfg.add(JLabel("Wordlist:"), gbc)
        wl_panel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        self.fuzz_wl_label = JLabel("No file loaded")
        self.fuzz_wl_label.setFont(Font("Monospaced", Font.PLAIN, 11))
        btn_wl = JButton("Browse...", actionPerformed=self.load_wordlist)
        btn_wl.setPreferredSize(Dimension(80, 22))
        wl_panel.add(btn_wl)
        wl_panel.add(self.fuzz_wl_label)
        gbc.gridx = 1; gbc.weightx = 1
        cfg.add(wl_panel, gbc)
        row += 1

        self.progress = JProgressBar(0, 100)
        self.progress.setStringPainted(True)
        self.progress.setString("Idle")
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2; gbc.weightx = 1
        cfg.add(self.progress, gbc)
        row += 1

        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        self.btn_start = JButton("Start Fuzzing", actionPerformed=self.start_fuzz)
        self.btn_stop  = JButton("Stop",          actionPerformed=self.stop_fuzz)
        self.btn_clear_fuzz = JButton("Clear Results", actionPerformed=self.clear_results)
        self.btn_stop.setEnabled(False)
        btn_panel.add(self.btn_start)
        btn_panel.add(self.btn_stop)
        btn_panel.add(self.btn_clear_fuzz)

        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2
        cfg.add(btn_panel, gbc)

        self.result_model = DefaultTableModel(["#", "Status", "Endpoint", "Length", "Note"], 0)
        self.result_table = JTable(self.result_model)
        self.result_table.setAutoCreateRowSorter(True)
        self.result_table.setFont(Font("Monospaced", Font.PLAIN, 11))

        self.result_table.getColumnModel().getColumn(0).setPreferredWidth(35)
        self.result_table.getColumnModel().getColumn(1).setPreferredWidth(55)
        self.result_table.getColumnModel().getColumn(2).setPreferredWidth(220)
        self.result_table.getColumnModel().getColumn(3).setPreferredWidth(60)
        self.result_table.getColumnModel().getColumn(4).setPreferredWidth(80)

        self.result_table.addMouseListener(FuzzTableMouseListener(self))
        result_scroll = JScrollPane(self.result_table)

        self.fuzz_req_text = JTextArea(8, 40)
        self.fuzz_req_text.setEditable(False)
        self.fuzz_req_text.setFont(Font("Monospaced", Font.PLAIN, 11))
        self.fuzz_req_text.setText("[ Click a result row to preview the request ]")
        fuzz_req_scroll = JScrollPane(self.fuzz_req_text)
        fuzz_req_scroll.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), " Request Preview (dbl-click -> Repeater) "))

        result_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, result_scroll, fuzz_req_scroll)
        result_split.setResizeWeight(0.6)
        result_split.setOneTouchExpandable(True)

        self.stats_label = JLabel("Results: 0  |  Sent: 0  |  Errors: 0")
        self.stats_label.setFont(Font("Monospaced", Font.PLAIN, 11))

        top_wrap = JPanel(BorderLayout())
        top_wrap.add(cfg, BorderLayout.CENTER)

        self.add(top_wrap, BorderLayout.NORTH)
        self.add(result_split, BorderLayout.CENTER)
        self.add(self.stats_label, BorderLayout.SOUTH)

    # ---- Wordlist loader ----
    def load_wordlist(self, event):
        fc = JFileChooser()
        if fc.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            path = fc.getSelectedFile().getAbsolutePath()
            try:
                with open(path, 'r') as f:
                    lines = [l.strip() for l in f.readlines() if l.strip() and not l.startswith('#')]
                self._wordlist = lines
                short = fc.getSelectedFile().getName()
                self.fuzz_wl_label.setText(" %s (%d words)" % (short, len(lines)))
            except Exception as e:
                self.fuzz_wl_label.setText(" Error: %s" % str(e))

    # ---- Start / Stop ----
    def start_fuzz(self, event):
        if not self._wordlist:
            self.stats_label.setText("Load a wordlist first!")
            return
        target = self.fuzz_host.getText().strip().rstrip('/')
        if not target:
            self.stats_label.setText("Enter a target host!")
            return

        self._stop_flag[0] = False
        self._sent[0]  = 0
        self._found[0] = 0
        self._errors[0] = 0
        self.result_model.setRowCount(0)
        self.progress.setValue(0)
        self.progress.setString("Starting...")
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)

        auth_note = " [Auth: %s]" % AUTH_MANAGER.get_auth_type() if AUTH_MANAGER.is_enabled() else " [Auth: OFF]"
        self.stats_label.setText("Running..." + auth_note)

        t = Thread(FuzzRunnable(self))
        t.setDaemon(True)
        t.start()

    def stop_fuzz(self, event):
        self._stop_flag[0] = True
        self.progress.setString("Stopping...")
        self.btn_stop.setEnabled(False)

    def clear_results(self, event):
        self.result_model.setRowCount(0)
        self._sent[0]  = 0
        self._found[0] = 0
        self._errors[0] = 0
        self.progress.setValue(0)
        self.progress.setString("Idle")
        self.stats_label.setText("Results: 0  |  Sent: 0  |  Errors: 0")

    # ---- Core fuzzing logic ----
    def do_fuzz(self):
        target_raw = self.fuzz_host.getText().strip().rstrip('/')
        base_path  = self.fuzz_base.getText().strip()
        method     = str(self.fuzz_method.getSelectedItem())
        extra_hdrs_raw = self.fuzz_headers.getText().strip()
        hide_raw   = self.fuzz_hide.getText().strip()
        total      = len(self._wordlist)

        hide_codes = set()
        for c in hide_raw.split(','):
            c = c.strip()
            if c.isdigit():
                hide_codes.add(int(c))

        try:
            parsed = urlparse.urlparse(target_raw)
            scheme = parsed.scheme or "https"
            host   = parsed.netloc or parsed.path
            port   = 443 if scheme == "https" else 80
            if ':' in host:
                host, port_str = host.rsplit(':', 1)
                port = int(port_str)
            use_ssl = (scheme == "https")
        except Exception as e:
            self._finish_fuzz("Parse error: %s" % str(e))
            return

        extra_headers = []
        if extra_hdrs_raw:
            for line in extra_hdrs_raw.split('\n'):
                line = line.strip()
                if ':' in line:
                    extra_headers.append(line)
        extra_headers = AUTH_MANAGER.inject(extra_headers)

        if not base_path.endswith('/'):
            base_path += '/'

        num_threads = int(self.fuzz_threads.getValue())
        wordlist = list(self._wordlist)

        from java.util.concurrent import LinkedBlockingQueue, Executors, TimeUnit
        queue = LinkedBlockingQueue()
        for word in wordlist:
            queue.put(word)

        pool = Executors.newFixedThreadPool(num_threads)

        class WorkerRunnable(Runnable):
            def __init__(self, fzp):
                self.fzp = fzp
            def run(self):
                while not self.fzp._stop_flag[0]:
                    word = queue.poll()
                    if word is None:
                        break
                    word = word.lstrip('/')
                    path = base_path + word
                    self.fzp._fuzz_one(host, port, use_ssl, method, path,
                                       extra_headers, hide_codes, total)

        for _ in range(num_threads):
            pool.submit(WorkerRunnable(self))

        pool.shutdown()
        pool.awaitTermination(300, TimeUnit.SECONDS)

        self._finish_fuzz("Done. Sent: %d | Found: %d | Errors: %d" % (
            self._sent[0], self._found[0], self._errors[0]))

    def _fuzz_one(self, host, port, use_ssl, method, path, extra_headers, hide_codes, total):
        try:
            req_lines = [
                "%s %s HTTP/1.1" % (method, path),
                "Host: %s" % host,
                "User-Agent: Mozilla/5.0 (compatible; Burp-Fuzzer)",
                "Accept: */*",
                "Connection: close",
            ]
            req_lines.extend(extra_headers)
            raw_req = "\r\n".join(req_lines) + "\r\n\r\n"

            service = self._helpers.buildHttpService(host, port, use_ssl)
            resp = self._callbacks.makeHttpRequest(service, bytearray(raw_req.encode('utf-8')))

            status = 0
            length = 0
            note   = ""

            if resp is not None:
                resp_bytes = resp.getResponse()
                if resp_bytes:
                    analyzed = self._helpers.analyzeResponse(resp_bytes)
                    status = analyzed.getStatusCode()
                    length = len(resp_bytes) - analyzed.getBodyOffset()
                    if status in (200, 201, 204):
                        note = "OK"
                    elif status in (301, 302, 307, 308):
                        note = "REDIRECT"
                    elif status == 401:
                        note = "AUTH REQ"
                    elif status == 403:
                        note = "FORBIDDEN"
                    elif status == 500:
                        note = "SERVER ERR"

            self._sent[0] += 1

            if status not in hide_codes:
                self._found[0] += 1
                row_num      = self._found[0]
                full_path    = path
                final_status = status
                final_length = length
                final_note   = note

                def add_row():
                    self.result_model.addRow([
                        str(row_num), str(final_status),
                        full_path, str(final_length), final_note
                    ])
                SwingUtilities.invokeLater(add_row)

            sent_now = self._sent[0]
            pct = int(float(sent_now) / total * 100) if total > 0 else 0

            def update_progress():
                self.progress.setValue(pct)
                self.progress.setString("%d / %d" % (sent_now, total))
                self.stats_label.setText(
                    "Results: %d  |  Sent: %d  |  Errors: %d" % (
                        self._found[0], self._sent[0], self._errors[0]))
            SwingUtilities.invokeLater(update_progress)

        except Exception as e:
            self._errors[0] += 1

    def _finish_fuzz(self, msg):
        def done():
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.progress.setValue(100)
            self.progress.setString("Complete")
            self.stats_label.setText(msg)
        SwingUtilities.invokeLater(done)

    def show_fuzz_request(self, row):
        try:
            target_raw = self.fuzz_host.getText().strip().rstrip('/')
            parsed = urlparse.urlparse(target_raw)
            scheme = parsed.scheme or "https"
            host   = parsed.netloc or parsed.path

            path   = str(self.result_model.getValueAt(row, 2))
            status = str(self.result_model.getValueAt(row, 1))
            length = str(self.result_model.getValueAt(row, 3))
            method = str(self.fuzz_method.getSelectedItem())

            extra_hdrs_raw = self.fuzz_headers.getText().strip()
            extra_headers  = []
            if extra_hdrs_raw:
                for line in extra_hdrs_raw.split('\n'):
                    line = line.strip()
                    if ':' in line:
                        extra_headers.append(line)
            extra_headers = AUTH_MANAGER.inject(extra_headers)

            lines = [
                "%s %s HTTP/1.1" % (method, path),
                "Host: %s" % host,
                "User-Agent: Mozilla/5.0 (compatible; Burp-Fuzzer)",
                "Accept: */*",
                "Connection: close",
            ]
            lines.extend(extra_headers)
            req_str = "\n".join(lines) + "\n\n"

            info = "[ Response Status: %s  |  Body Length: %s bytes  |  Dbl-click -> Repeater ]\n\n" % (status, length)
            self.fuzz_req_text.setText(info + req_str)
            self.fuzz_req_text.setCaretPosition(0)
        except Exception as e:
            self.fuzz_req_text.setText("Error building preview: %s" % str(e))

    def send_result_to_repeater(self, row):
        try:
            target_raw = self.fuzz_host.getText().strip().rstrip('/')
            parsed = urlparse.urlparse(target_raw)
            scheme = parsed.scheme or "https"
            host   = parsed.netloc or parsed.path
            port   = 443 if scheme == "https" else 80
            if ':' in host:
                host, port_str = host.rsplit(':', 1)
                port = int(port_str)

            path   = str(self.result_model.getValueAt(row, 2))
            method = str(self.fuzz_method.getSelectedItem())

            extra_hdrs_raw = self.fuzz_headers.getText().strip()
            extra_headers  = []
            if extra_hdrs_raw:
                for line in extra_hdrs_raw.split('\n'):
                    line = line.strip()
                    if ':' in line:
                        extra_headers.append(line)
            extra_headers = AUTH_MANAGER.inject(extra_headers)

            req_lines = [
                "%s %s HTTP/1.1" % (method, path),
                "Host: %s" % host,
                "User-Agent: Mozilla/5.0 (compatible; Burp-Fuzzer)",
                "Accept: */*",
                "Connection: close",
            ]
            req_lines.extend(extra_headers)
            raw_req = "\r\n".join(req_lines) + "\r\n\r\n"

            tab_name = "FUZZ %s %s" % (method, path[:40])
            self._callbacks.sendToRepeater(
                host, port, scheme == "https",
                bytearray(raw_req.encode('utf-8')),
                tab_name
            )
        except Exception as e:
            print("Repeater send error: %s" % str(e))


# ====================== FUZZ TABLE MOUSE LISTENER ======================
class FuzzTableMouseListener(MouseAdapter):
    def __init__(self, fuzzer_panel):
        self.fp = fuzzer_panel

    def mouseClicked(self, event):
        row = self.fp.result_table.rowAtPoint(event.getPoint())
        if row < 0:
            return
        model_row = self.fp.result_table.getRowSorter().convertRowIndexToModel(row)
        if event.getClickCount() == 1:
            self.fp.show_fuzz_request(model_row)
        elif event.getClickCount() == 2:
            self.fp.send_result_to_repeater(model_row)


# ====================== MAIN EXTENDER ======================
class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("API Collection Importer - Ultimate")

        self.panel = JPanel(BorderLayout())
        self.current_endpoints = []
        self.variables     = {}
        self.env_variables = {}

        # ====================== TOP PANEL ======================
        top_panel = JPanel(FlowLayout(FlowLayout.LEFT))

        self.btn_load_collection = JButton("Load Postman Collection", actionPerformed=self.load_collection)
        self.btn_load_env        = JButton("Load Environment File",   actionPerformed=self.load_environment)
        self.btn_clear           = JButton("Clear Table",             actionPerformed=self.clear_table)

        self.host_combo = JComboBox()
        self.host_combo.setPreferredSize(Dimension(250, 25))

        top_panel.add(JLabel("Host: "))
        top_panel.add(self.host_combo)
        top_panel.add(self.btn_load_collection)
        top_panel.add(self.btn_load_env)
        top_panel.add(self.btn_clear)

        self.search_field = JTextField(20)
        self.search_field.getDocument().addDocumentListener(SearchListener(self))
        top_panel.add(JLabel("   Search: "))
        top_panel.add(self.search_field)

        self.btn_import_all             = JButton("Load All to Target",        actionPerformed=self.import_all_to_target)
        self.btn_send_all_repeater      = JButton("Send All to Repeater",      actionPerformed=self.send_all_to_repeater)
        self.btn_send_selected_repeater = JButton("Send Selected -> Repeater", actionPerformed=self.send_selected_to_repeater)
        self.btn_send_selected_intruder = JButton("Send Selected -> Intruder", actionPerformed=self.send_selected_to_intruder)

        self.btn_import_all.setEnabled(False)
        self.btn_send_all_repeater.setEnabled(False)

        top_panel.add(self.btn_import_all)
        top_panel.add(self.btn_send_all_repeater)
        top_panel.add(self.btn_send_selected_repeater)
        top_panel.add(self.btn_send_selected_intruder)

        # ====================== TABLE ======================
        self.table_model = DefaultTableModel(["Name", "Folder", "Method", "Path", "Full URL"], 0)
        self.table = JTable(self.table_model)
        self.table.setAutoCreateRowSorter(True)
        self.table.setRowSorter(TableRowSorter(self.table_model))
        self.table.addMouseListener(TableMouseListener(self))

        table_scroll = JScrollPane(self.table)
        table_scroll.setPreferredSize(Dimension(900, 300))

        # ====================== REQUEST VIEWER ======================
        self.request_text = JTextArea(18, 90)
        self.request_text.setEditable(False)
        self.request_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        request_scroll = JScrollPane(self.request_text)

        self.status_label = JLabel("Ready. Load a Postman collection to begin.")

        left_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, request_scroll)
        left_split.setResizeWeight(0.55)

        left_panel = JPanel(BorderLayout())
        left_panel.add(top_panel,         BorderLayout.NORTH)
        left_panel.add(left_split,        BorderLayout.CENTER)
        left_panel.add(self.status_label, BorderLayout.SOUTH)

        # ====================== FUZZER PANEL (right) ======================
        self.fuzzer_panel = FuzzerPanel(callbacks, self._helpers)
        self.host_combo.addActionListener(self._sync_fuzzer_host)

        # ====================== AUTH PANEL ======================
        self.auth_panel = AuthPanel()

        right_column = JPanel(BorderLayout(4, 4))
        right_column.add(self.auth_panel,   BorderLayout.NORTH)
        right_column.add(self.fuzzer_panel, BorderLayout.CENTER)

        # ====================== MAIN SPLIT ======================
        main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left_panel, right_column)
        main_split.setResizeWeight(0.72)
        main_split.setDividerLocation(0.72)
        main_split.setOneTouchExpandable(True)

        self.panel.add(main_split, BorderLayout.CENTER)

        # ====================== GLOBAL ZOOM ======================
        self._zoom = GlobalZoomDispatcher()
        self._zoom.register(self.request_text)
        self._zoom.register(self.table)
        self._zoom.register(self.fuzzer_panel.result_table)
        self._zoom.register(self.fuzzer_panel.fuzz_req_text)
        self._zoom.register(self.status_label)
        self._zoom.register(self.fuzzer_panel.stats_label)
        KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(self._zoom)

        callbacks.addSuiteTab(self)
        print("API Collection Importer + Fuzzer + Multi-Auth loaded!")
        print("Supported auth types: %s" % ", ".join(ALL_AUTH_TYPES))

    def _sync_fuzzer_host(self, event):
        selected = self.host_combo.getSelectedItem()
        if selected:
            scheme = "https"
            for ep in self.current_endpoints:
                parsed = urlparse.urlparse(ep.get('full_url', ''))
                if parsed.netloc == str(selected):
                    scheme = parsed.scheme or "https"
                    break
            self.fuzzer_panel.fuzz_host.setText("%s://%s" % (scheme, str(selected)))

    def getTabCaption(self):
        return "API Importer Ultimate"

    def getUiComponent(self):
        return self.panel

    # ====================== VARIABLE RESOLVER ======================
    def resolve_variables(self, text):
        if not text:
            return text
        for k, v in self.variables.items():
            text = text.replace("{{" + k + "}}", str(v))
        for k, v in self.env_variables.items():
            text = text.replace("{{" + k + "}}", str(v))
        return text

    # ====================== PARSER ======================
    def parse_collection(self, data):
        endpoints = []
        hosts = set()

        def extract_items(items, parent_folder=""):
            for item in items:
                if not isinstance(item, dict):
                    continue
                name = item.get('name', 'Unnamed')

                if 'request' in item:
                    req    = item['request']
                    method = req.get('method', 'GET').upper()
                    url_obj  = req.get('url', {})
                    full_url = ""
                    path     = "/"
                    host     = "unknown"

                    if isinstance(url_obj, dict):
                        if url_obj.get('raw'):
                            raw      = str(url_obj['raw'])
                            full_url = self.resolve_variables(raw)
                            try:
                                p    = urlparse.urlparse(full_url)
                                host = p.netloc or host
                                path = p.path or '/'
                                if p.query:
                                    path += '?' + p.query
                            except:
                                pass
                        else:
                            host_parts = url_obj.get('host', [])
                            host = ".".join(str(x) for x in host_parts) if host_parts else host
                            path_parts = url_obj.get('path', [])
                            path = '/' + '/'.join(str(x) for x in path_parts).lstrip('/')
                            query = url_obj.get('query', [])
                            if query:
                                qlist = []
                                for q in query:
                                    k = self.resolve_variables(q.get('key', ''))
                                    v = self.resolve_variables(q.get('value', ''))
                                    if k:
                                        qlist.append("%s=%s" % (k, v))
                                if qlist:
                                    path += '?' + '&'.join(qlist)

                    headers = []
                    for h in req.get('header', []):
                        key = self.resolve_variables(h.get('key', ''))
                        val = self.resolve_variables(h.get('value', ''))
                        if key:
                            headers.append("%s: %s" % (key, val))

                    body     = ""
                    body_obj = req.get('body', {})
                    if body_obj.get('raw'):
                        body = self.resolve_variables(body_obj['raw'])

                    full_url = full_url or "https://%s%s" % (host, path)
                    hosts.add(host)

                    endpoints.append({
                        'name':     name,
                        'folder':   parent_folder,
                        'method':   method,
                        'path':     path,
                        'full_url': full_url,
                        'host':     host,
                        'headers':  headers,
                        'body':     body
                    })

                elif 'item' in item and isinstance(item.get('item'), list):
                    new_folder = "%s/%s" % (parent_folder, name) if parent_folder else name
                    extract_items(item['item'], new_folder)

        if 'variable' in data:
            for v in data.get('variable', []):
                if v.get('key'):
                    self.variables[v['key']] = v.get('value', '')

        extract_items(data.get('item', []))
        return endpoints, list(hosts)

    # ====================== LOAD COLLECTION ======================
    def load_collection(self, event):
        fc = JFileChooser()
        if fc.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            file_path = fc.getSelectedFile().getAbsolutePath()
            self.status_label.setText("Parsing: %s" % file_path)
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)

                endpoints, hosts = self.parse_collection(data)

                self.host_combo.removeAllItems()
                for h in sorted(hosts):
                    if h and h != "unknown":
                        self.host_combo.addItem(h)

                self.table_model.setRowCount(0)
                for ep in endpoints:
                    self.table_model.addRow([
                        ep['name'], ep['folder'], ep['method'],
                        ep['path'], ep['full_url']
                    ])

                self.current_endpoints = endpoints
                self.btn_import_all.setEnabled(True)
                self.btn_send_all_repeater.setEnabled(True)
                self.status_label.setText("Loaded %d endpoints successfully!" % len(endpoints))

            except Exception as e:
                self.status_label.setText("Error: %s" % str(e))

    # ====================== LOAD ENVIRONMENT ======================
    def load_environment(self, event):
        fc = JFileChooser()
        if fc.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            path = fc.getSelectedFile().getAbsolutePath()
            try:
                with open(path, 'r') as f:
                    data = json.load(f)
                self.env_variables = {}
                for v in data.get('values', []):
                    if v.get('key'):
                        self.env_variables[v['key']] = v.get('value', '')
                self.status_label.setText("Environment loaded (%d variables)" % len(self.env_variables))
            except Exception as e:
                self.status_label.setText("Env error: %s" % str(e))

    # ====================== BUILD RAW HTTP REQUEST ======================
    def build_raw_request(self, ep, host):
        body_bytes = ep['body'].encode('utf-8') if ep['body'] else b""

        merged_headers = list(ep['headers'])
        merged_headers = AUTH_MANAGER.inject(merged_headers)

        # Handle API Key in query param: append to path if needed
        path = ep['path']
        qp = AUTH_MANAGER.get_query_param()
        if qp:
            sep = '&' if '?' in path else '?'
            path = "%s%s%s=%s" % (path, sep, qp[0], qp[1])

        existing_keys = set()
        for h in merged_headers:
            if ':' in h:
                existing_keys.add(h.split(':', 1)[0].strip().lower())

        lines = []
        lines.append("%s %s HTTP/1.1" % (ep['method'], path))
        lines.append("Host: %s" % host)
        if 'user-agent' not in existing_keys:
            lines.append("User-Agent: Mozilla/5.0 (compatible; Burp Suite)")
        if 'accept' not in existing_keys:
            lines.append("Accept: */*")
        if body_bytes and 'content-type' not in existing_keys:
            lines.append("Content-Type: application/json")
        if body_bytes:
            lines.append("Content-Length: %d" % len(body_bytes))
        for h in merged_headers:
            if ':' in h:
                key = h.split(':', 1)[0].strip().lower()
                if key == 'host':
                    continue
                lines.append(h)
        lines.append("Connection: close")

        header_section = "\r\n".join(lines) + "\r\n\r\n"
        raw = bytearray(header_section.encode('utf-8')) + bytearray(body_bytes)
        return bytes(raw)

    # ====================== REQUEST VIEWER ======================
    def build_full_request(self, ep):
        parsed = urlparse.urlparse(ep['full_url'])
        host   = parsed.netloc or str(self.host_combo.getSelectedItem() or "example.com")

        merged_headers = list(ep['headers'])
        merged_headers = AUTH_MANAGER.inject(merged_headers)

        path = ep['path']
        qp = AUTH_MANAGER.get_query_param()
        if qp:
            sep = '&' if '?' in path else '?'
            path = "%s%s%s=%s" % (path, sep, qp[0], qp[1])

        existing_keys = set()
        for h in merged_headers:
            if ':' in h:
                existing_keys.add(h.split(':', 1)[0].strip().lower())

        lines = ["%s %s HTTP/1.1" % (ep['method'], path), "Host: %s" % host]
        if 'user-agent' not in existing_keys:
            lines.append("User-Agent: Mozilla/5.0 (compatible; Burp Suite)")
        if 'accept' not in existing_keys:
            lines.append("Accept: */*")
        body_bytes = ep['body'].encode('utf-8') if ep['body'] else b""
        if body_bytes and 'content-type' not in existing_keys:
            lines.append("Content-Type: application/json")
        if body_bytes:
            lines.append("Content-Length: %d" % len(body_bytes))
        for h in merged_headers:
            if ':' in h:
                key = h.split(':', 1)[0].strip().lower()
                if key != 'host':
                    lines.append(h)
        lines.append("Connection: close")
        return "\n".join(lines) + "\n\n" + ep['body']

    def single_click(self, row):
        if row < 0:
            return
        ep = self.current_endpoints[row]
        self.request_text.setText(self.build_full_request(ep))
        self.status_label.setText("Viewing: %s %s" % (ep['method'], ep['name']))

    def double_click(self, row):
        if row < 0:
            return
        self.send_to_repeater(row)

    # ====================== SEND TO REPEATER ======================
    def send_to_repeater(self, row):
        ep = self.current_endpoints[row]
        try:
            parsed = urlparse.urlparse(ep['full_url'])
            host   = parsed.netloc or str(self.host_combo.getSelectedItem() or "example.com")
            scheme = parsed.scheme or "https"
            port   = 443 if scheme == "https" else 80
            if ':' in host:
                host, port_str = host.rsplit(':', 1)
                port = int(port_str)

            request_bytes = self.build_raw_request(ep, host)
            tab_name = "%s %s" % (ep['method'], ep['name'][:40])
            self._callbacks.sendToRepeater(host, port, scheme == "https", request_bytes, tab_name)
            self.status_label.setText("Sent to Repeater: %s" % ep['name'])
        except Exception as e:
            self.status_label.setText("Repeater error: %s" % str(e))

    def send_all_to_repeater(self, event):
        for i in range(len(self.current_endpoints)):
            self.send_to_repeater(i)
        self.status_label.setText("All %d requests sent to Repeater" % len(self.current_endpoints))

    def send_selected_to_repeater(self, event):
        rows = [self.table.getRowSorter().convertRowIndexToModel(r) for r in self.table.getSelectedRows()]
        for r in rows:
            self.send_to_repeater(r)
        self.status_label.setText("%d selected request(s) sent to Repeater" % len(rows))

    # ====================== SEND TO INTRUDER ======================
    def send_selected_to_intruder(self, event):
        rows = [self.table.getRowSorter().convertRowIndexToModel(r) for r in self.table.getSelectedRows()]
        if not rows:
            self.status_label.setText("Select at least one row")
            return
        for r in rows:
            ep = self.current_endpoints[r]
            try:
                parsed = urlparse.urlparse(ep['full_url'])
                host   = parsed.netloc or str(self.host_combo.getSelectedItem() or "example.com")
                scheme = parsed.scheme or "https"
                port   = 443 if scheme == "https" else 80
                if ':' in host:
                    host, port_str = host.rsplit(':', 1)
                    port = int(port_str)
                request_bytes = self.build_raw_request(ep, host)
                self._callbacks.sendToIntruder(host, port, scheme == "https", request_bytes, True)
            except:
                pass
        self.status_label.setText("%d request(s) sent to Intruder" % len(rows))

    # ====================== IMPORT ALL TO TARGET ======================
    def import_all_to_target(self, event):
        success = 0
        failed  = 0
        for ep in self.current_endpoints:
            try:
                parsed = urlparse.urlparse(ep['full_url'])
                host   = parsed.netloc or str(self.host_combo.getSelectedItem() or "example.com")
                scheme = parsed.scheme or "https"
                port   = 443 if scheme == "https" else 80
                if ':' in host:
                    host, port_str = host.rsplit(':', 1)
                    port = int(port_str)

                request_bytes = self.build_raw_request(ep, host)
                service = CustomHttpService(host, port, scheme)
                http_rr = CustomHttpRequestResponse(service, request_bytes)
                self._callbacks.addToSiteMap(http_rr)
                success += 1
            except Exception as e:
                failed += 1
                print("SiteMap error [%s]: %s" % (ep.get('name', '?'), str(e)))

        self.status_label.setText(
            "Site map updated: %d added, %d failed. Check Target > Site map." % (success, failed)
        )

    def clear_table(self, event):
        self.table_model.setRowCount(0)
        self.current_endpoints = []
        self.btn_import_all.setEnabled(False)
        self.btn_send_all_repeater.setEnabled(False)
        self.request_text.setText("")
        self.status_label.setText("Table cleared.")


# ====================== MOUSE LISTENER ======================
class TableMouseListener(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender

    def mouseClicked(self, event):
        row = self.extender.table.rowAtPoint(event.getPoint())
        if row < 0:
            return
        model_row = self.extender.table.getRowSorter().convertRowIndexToModel(row)
        if event.getClickCount() == 1:
            self.extender.single_click(model_row)
        elif event.getClickCount() == 2:
            self.extender.double_click(model_row)


# ====================== LIVE SEARCH ======================
class SearchListener(DocumentListener):
    def __init__(self, extender):
        self.extender = extender

    def insertUpdate(self, e):  self.filter()
    def removeUpdate(self, e):  self.filter()
    def changedUpdate(self, e): self.filter()

    def filter(self):
        import re as _re
        from javax.swing import RowFilter
        text   = self.extender.search_field.getText().strip()
        sorter = self.extender.table.getRowSorter()
        if text:
            escaped = _re.escape(text)
            sorter.setRowFilter(RowFilter.regexFilter("(?i)" + escaped))
        else:
            sorter.setRowFilter(None)
            sorter.setRowFilter(None)
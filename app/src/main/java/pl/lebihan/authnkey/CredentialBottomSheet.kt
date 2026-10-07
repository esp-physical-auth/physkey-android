package pl.lebihan.authnkey

import android.animation.ObjectAnimator
import android.content.Context
import android.content.DialogInterface
import android.content.res.ColorStateList
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.AccelerateDecelerateInterpolator
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.google.android.material.button.MaterialButton

class CredentialBottomSheet : BottomSheetDialogFragment() {

    enum class State {
        WAITING,
        TOUCH,
        PROCESSING,
        PIN,
        BIOMETRIC,
        ACCOUNT_SELECT,
        SUCCESS,
        TAG_LOST,
        ERROR
    }

    data class AccountInfo(
        val displayName: String,
        val subtitle: String? = null
    )

    private lateinit var statusText: TextView
    private lateinit var instructionText: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var btnCancel: MaterialButton
    private lateinit var btnContinue: MaterialButton
    private lateinit var btnBiometric: MaterialButton
    private lateinit var pinInputField: PinInputField
    private lateinit var iconStatus: ImageView
    private lateinit var iconBackground: View
    private lateinit var accountList: RecyclerView
    private lateinit var nfcHintContainer: View
    private lateinit var btnNfcSettings: MaterialButton
    private lateinit var btnConnectEsp32: MaterialButton

    private var pulseAnimator: ObjectAnimator? = null

    private var pendingStatus: String? = null
    private var pendingInstruction: String? = null
    private var pendingShowPinInput: Boolean = false
    private var pendingShowNfcHint: Boolean = false
    private var pendingShowEsp32Button: Boolean = false
    private var pendingState: State = State.WAITING

    var onCancelClick: (() -> Unit)? = null
    var onPinEntered: ((String) -> Unit)? = null
    var onAccountSelected: ((Int) -> Unit)? = null
    var onBiometricSelected: (() -> Unit)? = null
    var onNfcSettingsClick: (() -> Unit)? = null
    var onConnectEsp32Click: (() -> Unit)? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        arguments?.let {
            pendingStatus = it.getString(ARG_STATUS)
            pendingInstruction = it.getString(ARG_INSTRUCTION)
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.bottom_sheet_credential, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        statusText = view.findViewById(R.id.statusText)
        instructionText = view.findViewById(R.id.instructionText)
        progressBar = view.findViewById(R.id.progressBar)
        btnCancel = view.findViewById(R.id.btnCancel)
        btnContinue = view.findViewById(R.id.btnContinue)
        btnBiometric = view.findViewById(R.id.btnBiometric)
        pinInputField = view.findViewById(R.id.pinInputField)
        iconStatus = view.findViewById(R.id.iconStatus)
        iconBackground = view.findViewById(R.id.iconBackground)
        accountList = view.findViewById(R.id.accountList)
        nfcHintContainer = view.findViewById(R.id.nfcHintContainer)
        btnNfcSettings = view.findViewById(R.id.btnNfcSettings)
        btnConnectEsp32 = view.findViewById(R.id.btnConnectEsp32)

        accountList.layoutManager = LinearLayoutManager(context)

        // Configure PIN input field
        pinInputField.useNumericKeyboard = getKeyboardPreference()
        pinInputField.onKeyboardModeChanged = { saveKeyboardPreference(it) }

        pendingStatus?.let { statusText.text = it }
        pendingInstruction?.let { instructionText.text = it }

        nfcHintContainer.visibility = if (pendingShowNfcHint) View.VISIBLE else View.GONE
        btnConnectEsp32.visibility = if (pendingShowEsp32Button) View.VISIBLE else View.GONE

        // 【已屏蔽】PIN 输入界面不在调用时展示（保留底层代码备用）。
        pinInputField.visibility = View.GONE
        btnContinue.visibility = View.GONE

        applyState(pendingState)

        btnCancel.setOnClickListener {
            onCancelClick?.invoke()
        }

        btnContinue.setOnClickListener {
            submitPin()
        }

        btnBiometric.setOnClickListener {
            onBiometricSelected?.invoke()
        }

        btnNfcSettings.setOnClickListener {
            onNfcSettingsClick?.invoke()
        }

        btnConnectEsp32.setOnClickListener {
            onConnectEsp32Click?.invoke()
        }

        pinInputField.setOnDoneAction {
            submitPin()
        }

        (dialog as? BottomSheetDialog)?.behavior?.apply {
            state = BottomSheetBehavior.STATE_EXPANDED
            skipCollapsed = true
        }
    }

    override fun onDestroyView() {
        stopPulse()
        super.onDestroyView()
    }

    override fun onCancel(dialog: DialogInterface) {
        super.onCancel(dialog)
        onCancelClick?.invoke()
    }

    private fun submitPin() {
        pinInputField.validateAndGetPin()?.let { pin ->
            onPinEntered?.invoke(pin)
        }
    }

    private fun getKeyboardPreference(): Boolean =
        requireContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(PREF_USE_NUMERIC_KEYBOARD, true)

    private fun saveKeyboardPreference(numeric: Boolean) {
        requireContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit { putBoolean(PREF_USE_NUMERIC_KEYBOARD, numeric) }
    }

    fun setState(state: State) {
        if (::iconStatus.isInitialized) {
            applyState(state)
        } else {
            pendingState = state
        }
    }

    private fun applyState(state: State) {
        stopPulse()

        val iconRes = when (state) {
            State.WAITING -> R.drawable.sensors_24
            State.TOUCH -> R.drawable.fingerprint_24
            State.PROCESSING -> R.drawable.key_24
            State.PIN -> R.drawable.lock_24
            State.BIOMETRIC -> R.drawable.fingerprint_24
            State.ACCOUNT_SELECT -> R.drawable.account_circle_24
            State.SUCCESS -> R.drawable.check_circle_24
            State.TAG_LOST -> R.drawable.sensors_24
            State.ERROR -> R.drawable.error_24
        }

        iconStatus.setImageResource(iconRes)
        iconBackground.backgroundTintList = null

        when (state) {
            State.WAITING, State.TOUCH, State.BIOMETRIC -> startPulse()
            State.TAG_LOST -> {
                iconBackground.backgroundTintList = ColorStateList.valueOf(
                    ContextCompat.getColor(requireContext(), R.color.warning_container)
                )
                startPulse(750)
            }
            else -> {}
        }
    }

    private fun startPulse(durationMs: Long = 1000) {
        pulseAnimator = ObjectAnimator.ofFloat(iconBackground, View.ALPHA, 1f, 0.3f).apply {
            duration = durationMs
            repeatCount = ObjectAnimator.INFINITE
            repeatMode = ObjectAnimator.REVERSE
            interpolator = AccelerateDecelerateInterpolator()
            start()
        }
    }

    private fun stopPulse() {
        pulseAnimator?.cancel()
        pulseAnimator = null
        if (::iconBackground.isInitialized) {
            iconBackground.alpha = 1f
        }
    }

    fun setStatus(text: String) {
        if (::statusText.isInitialized) {
            statusText.text = text
        } else {
            pendingStatus = text
        }
    }

    fun setInstruction(text: String) {
        if (::instructionText.isInitialized) {
            instructionText.text = text
        } else {
            pendingInstruction = text
        }
    }

    /** Shows the "NFC is off" row with a shortcut to system NFC settings. */
    fun showNfcHint(show: Boolean) {
        if (::nfcHintContainer.isInitialized) {
            nfcHintContainer.visibility = if (show) View.VISIBLE else View.GONE
        } else {
            pendingShowNfcHint = show
        }
    }

    fun showProgress(show: Boolean) {
        if (::progressBar.isInitialized) {
            progressBar.visibility = if (show) View.VISIBLE else View.GONE
        }
    }

    fun showPinInput(show: Boolean) {
        // 【已屏蔽】PIN 输入界面不在调用时展示，保留底层代码备用。
        // 无论传入什么，都不显示 PIN 输入框/继续按钮。
        if (::pinInputField.isInitialized) {
            pinInputField.visibility = View.GONE
            btnContinue.visibility = View.GONE
        }
        if (show) {
            // 本来要弹 PIN 输入：改为不显示，保留原状态（由上层走其他验证路径）
            pendingShowPinInput = false
        }
        hideBiometricOption()
    }

    fun showBiometricOption(show: Boolean) {
        if (::btnBiometric.isInitialized) {
            btnBiometric.visibility = if (show) View.VISIBLE else View.GONE
        }
    }

    /** 显示/隐藏“连接 ESP32 (BLE)”按钮。 */
    fun showEsp32Button(show: Boolean) {
        if (::btnConnectEsp32.isInitialized) {
            btnConnectEsp32.visibility = if (show) View.VISIBLE else View.GONE
        } else {
            pendingShowEsp32Button = show
        }
    }

    fun hideBiometricOption() {
        if (::btnBiometric.isInitialized) {
            btnBiometric.visibility = View.GONE
        }
    }

    fun showBiometricWaiting() {
        if (::pinInputField.isInitialized) {
            pinInputField.visibility = View.GONE
            btnContinue.visibility = View.GONE
            hideBiometricOption()
            hideAccounts()
            setState(State.BIOMETRIC)
        }
    }

    fun showAccounts(accounts: List<AccountInfo>) {
        if (!::accountList.isInitialized) return

        setState(State.ACCOUNT_SELECT)
        pinInputField.visibility = View.GONE
        btnContinue.visibility = View.GONE
        hideBiometricOption()
        accountList.visibility = View.VISIBLE
        accountList.adapter = AccountAdapter(accounts) { index ->
            onAccountSelected?.invoke(index)
        }
    }

    fun hideAccounts() {
        if (::accountList.isInitialized) {
            accountList.visibility = View.GONE
        }
    }

    fun setPinError(error: String?) {
        if (::pinInputField.isInitialized) {
            pinInputField.error = error
        }
    }

    fun getCurrentPinIfValid(): String? {
        if (!::pinInputField.isInitialized) return null
        val pin = pinInputField.pin ?: return null
        return if (pin.length >= pinInputField.minPinLength) pin else null
    }

    private class AccountAdapter(
        private val accounts: List<AccountInfo>,
        private val onItemClick: (Int) -> Unit
    ) : RecyclerView.Adapter<AccountAdapter.ViewHolder>() {

        class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val name: TextView = view.findViewById(R.id.accountName)
            val subtitle: TextView = view.findViewById(R.id.accountSubtitle)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_account, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val account = accounts[position]
            holder.name.text = account.displayName
            if (account.subtitle != null) {
                holder.subtitle.text = account.subtitle
                holder.subtitle.visibility = View.VISIBLE
            } else {
                holder.subtitle.visibility = View.GONE
            }
            holder.itemView.setOnClickListener {
                onItemClick(position)
            }
        }

        override fun getItemCount() = accounts.size
    }

    companion object {
        const val TAG = "CredentialBottomSheet"
        private const val ARG_STATUS = "status"
        private const val ARG_INSTRUCTION = "instruction"
        private const val PREFS_NAME = "authnkey_prefs"
        private const val PREF_USE_NUMERIC_KEYBOARD = "use_numeric_keyboard"

        fun newInstance(status: String, instruction: String): CredentialBottomSheet {
            return CredentialBottomSheet().apply {
                arguments = Bundle().apply {
                    putString(ARG_STATUS, status)
                    putString(ARG_INSTRUCTION, instruction)
                }
            }
        }
    }
}

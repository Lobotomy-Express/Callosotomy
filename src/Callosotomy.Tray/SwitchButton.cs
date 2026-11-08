using System.Windows.Controls;
using System.Windows.Controls.Primitives;

namespace Callosotomy.Tray;

/// <summary>
/// An on/off switch whose state always comes from the service. Clicking raises Click (on press,
/// so a list refresh between press and release can't swallow it) but doesn't flip IsChecked
/// itself: the switch moves when the service confirms the change.
/// </summary>
public sealed class SwitchButton : ToggleButton
{
    public SwitchButton() => ClickMode = ClickMode.Press;

    protected override void OnToggle()
    {
    }
}

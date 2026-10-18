using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace LocalVault.Desktop;

internal static class Ui
{
    public static TextBlock Text(string value, double size = 14, bool bold = false) => new()
    { Text = value, FontSize = size, FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal,
      TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) };
    public static Button Button(string value, Action action, bool primary = false)
    {
        var button = new Button { Content = value };
        if (primary) { button.Background = new SolidColorBrush(Color.FromRgb(47, 94, 225)); button.Foreground = Brushes.White; }
        button.Click += (_, _) => action();
        return button;
    }
    public static ScrollViewer Scroll(UIElement content) => new()
    { Content = content, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
    public static Border Card(UIElement content, double padding = 24) => new()
    { Child = content, Background = Brushes.White, CornerRadius = new CornerRadius(12), Padding = new Thickness(padding) };
}


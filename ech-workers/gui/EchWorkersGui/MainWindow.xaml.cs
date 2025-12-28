using System.Windows;
using EchWorkersGui.ViewModels;

namespace EchWorkersGui;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainViewModel();
    }
}

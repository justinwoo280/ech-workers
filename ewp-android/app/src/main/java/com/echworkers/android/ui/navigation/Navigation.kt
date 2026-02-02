package com.echworkers.android.ui.navigation

import androidx.compose.runtime.Composable
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.echworkers.android.ui.screen.AppSelectScreen
import com.echworkers.android.ui.screen.HomeScreen
import com.echworkers.android.ui.screen.NodeEditScreen
import com.echworkers.android.viewmodel.MainViewModel

sealed class Screen(val route: String) {
    object Home : Screen("home")
    object NodeEdit : Screen("node_edit/{nodeId}") {
        fun createRoute(nodeId: String = "new") = "node_edit/$nodeId"
    }
    object AppSelect : Screen("app_select")
}

@Composable
fun EWPNavHost(
    viewModel: MainViewModel,
    onRequestVpnPermission: () -> Unit
) {
    val navController = rememberNavController()
    
    NavHost(
        navController = navController,
        startDestination = Screen.Home.route
    ) {
        composable(Screen.Home.route) {
            HomeScreen(
                viewModel = viewModel,
                onNavigateToNodeEdit = { nodeId ->
                    navController.navigate(Screen.NodeEdit.createRoute(nodeId))
                },
                onNavigateToAppSelect = {
                    navController.navigate(Screen.AppSelect.route)
                },
                onRequestVpnPermission = onRequestVpnPermission
            )
        }
        
        composable(
            route = Screen.NodeEdit.route,
            arguments = listOf(
                navArgument("nodeId") { type = NavType.StringType }
            )
        ) { backStackEntry ->
            val nodeId = backStackEntry.arguments?.getString("nodeId") ?: "new"
            NodeEditScreen(
                viewModel = viewModel,
                nodeId = if (nodeId == "new") null else nodeId,
                onNavigateBack = { navController.popBackStack() }
            )
        }
        
        composable(Screen.AppSelect.route) {
            AppSelectScreen(
                viewModel = viewModel,
                onNavigateBack = { navController.popBackStack() }
            )
        }
    }
}

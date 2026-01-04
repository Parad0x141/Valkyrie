#pragma once

#include "Common.hpp"
#include <ostream>

inline void Splash()
{
	SetConsoleOutputCP(CP_UTF8);
	using namespace rang;

	static const std::array<const char*, 7> art = {
		"   :::     :::     :::     :::        :::    ::: :::   ::: :::::::::  ::::::::::: :::::::::: ",
		"  :+:     :+:   :+: :+:   :+:        :+:   :+:  :+:   :+: :+:    :+:     :+:     :+:         ",
		" +:+     +:+  +:+   +:+  +:+        +:+  +:+    +:+ +:+  +:+    +:+     +:+     +:+          ",
		"+#+     +:+ +#++:++#++: +#+        +#++:++      +#++:   +#++:++#:      +#+     +#++:++#       ",
		"+#+   +#+  +#+     +#+ +#+        +#+  +#+      +#+    +#+    +#+     +#+     +#+            ",
		"#+#+#+#   #+#     #+# #+#        #+#   #+#     #+#    #+#    #+#     #+#     #+#             ",
		" ###     ###     ### ########## ###    ###    ###    ###    ### ########### ##########       "
	};


	static const std::array<rang::fgB, 7> grad = {
		fgB::red, fgB::red, fgB::red,
		fgB::black, fgB::black, fgB::black,fgB::black
	};

	for (size_t i = 0; i < art.size(); ++i)
		std::cout << grad[i] << art[i] << '\n';

	std::cout << "\n";
	std::cout << style::bold
		<< "               Valkyrie Kernel Driver Mapper v0.4.2 by Parad0x141\n"
		<< style::reset << std::endl;
}


